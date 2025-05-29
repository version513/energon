use crate::traits::Affine;
use crate::traits::Group;
use crate::traits::Projective;
use crate::traits::ScalarField;
use crate::traits::Scheme;

use crate::backends::error::BackendsError;
use crate::points::KeyPoint;

use std::collections::BTreeMap;
use std::ops::Mul;

/// Public version of [`ScalarsXY`]
type CommitsXY<S> = BTreeMap<u32, (X<S>, KeyPoint<S>)>;
/// X:Scalar = pri_share.index + 1
type X<S> = <S as Scheme>::Scalar;
/// Y:Scalar = pri_share.value
type Y<S> = <S as Scheme>::Scalar;
/// ScalarsXY is a map with key:u32 = pri_share.index, value:(Scalar,Scalar) = (X,Y)
type ScalarsXY<S> = BTreeMap<u32, (X<S>, Y<S>)>;

#[derive(thiserror::Error, Debug)]
pub enum PolyError {
    #[error("different number of coefficients")]
    CoeffsError,
    #[error("recover private polynomial: not enough shares")]
    RecoverPriPolyNeedMoreShares,
    #[error("recover secret: scalar is not invertable")]
    RecoverSecretScalarIsNotInvertable,
    #[error("recover secret: not enough shares")]
    RecoverSecretNeedMoreShares,
    #[error("recover commitment: scalar is not invertable")]
    RecoverCommitmentScalarIsNotInvertable,
    #[error("recover commitment: not enough shares")]
    RecoverCommitmentNeedMoreShares,
    #[error("lagrange basis: xi is not found")]
    LagrangeBasisXi,
    #[error("lagrange basis: scalar is not invertable")]
    LagrangeBasisScalarIsNotInvertable,
}

#[derive(Default, PartialEq, Clone)]
pub struct PriShare<S: Scheme> {
    index: u32,
    value: S::Scalar,
}

impl<S: Scheme> PriShare<S> {
    pub fn new(index: u32, value: S::Scalar) -> Self {
        Self { index, value }
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn value(&self) -> &S::Scalar {
        &self.value
    }

    pub fn into_value(self) -> S::Scalar {
        self.value
    }
}

#[derive(Debug, Default, Clone)]
pub struct PriPoly<S: Scheme> {
    coeffs: Vec<S::Scalar>,
}

impl<S: Scheme> PriPoly<S> {
    /// Creates a new secret sharing polynomial using the provided
    /// secret sharing threshold and secret (if present).
    pub fn new(threshold: u32, secret: Option<S::Scalar>) -> Self {
        let mut coeffs = Vec::with_capacity(threshold as usize);
        if let Some(s) = secret {
            coeffs.push(s);
            for _ in 1..threshold {
                coeffs.push(ScalarField::random())
            }
        } else {
            for _ in 0..threshold {
                coeffs.push(ScalarField::random())
            }
        }

        Self { coeffs }
    }

    pub fn eval(&self, index: u32) -> PriShare<S> {
        let xi = S::Scalar::from_u64((1 + index).into());
        let mut value = S::Scalar::zero();
        for j in (0..self.threshold()).rev() {
            value *= &xi;
            value += &self.coeffs[j]
        }

        PriShare::new(index, value)
    }

    /// Multiples p and q together. The result is a polynomial of the sum of
    /// the two degrees of p and q.
    ///
    /// NOTE: This is only for use in secret sharing schemes. It is not
    /// a general polynomial multiplication routine.
    pub fn mul(p: &PriPoly<S>, q: &PriPoly<S>) -> PriPoly<S> {
        let d1 = p.coeffs.len() - 1;
        let d2 = q.coeffs.len() - 1;
        let new_degree = d1 + d2;
        let mut coeffs: Vec<S::Scalar> = vec![S::Scalar::zero(); new_degree + 1];

        for (i, p_i) in p.coeffs.iter().enumerate() {
            for (j, q_j) in q.coeffs.iter().enumerate() {
                coeffs[i + j] = p_i.mul(q_j) + &coeffs[i + j];
            }
        }

        PriPoly { coeffs }
    }

    pub fn add(&mut self, rhs: PriPoly<S>) -> Result<(), PolyError> {
        if self.threshold() != rhs.threshold() {
            return Err(PolyError::CoeffsError);
        }
        for (p_i, q_i) in self.coeffs.iter_mut().zip(&rhs.coeffs) {
            *p_i += q_i;
        }

        Ok(())
    }

    pub fn commit(&self) -> PubPoly<S> {
        let commits = (0..self.threshold())
            .map(|i| S::sk_to_pk(&self.coeffs[i]))
            .collect();

        PubPoly { commits }
    }

    pub fn secret(&self) -> &S::Scalar {
        &self.coeffs[0]
    }

    pub fn threshold(&self) -> usize {
        self.coeffs.len()
    }
}

/// Takes a list of shares and the parameters t and n to reconstruct
///  the secret polynomial completely, i.e., all private coefficients.
///
/// It is up to the caller to make sure that there are enough (at least t)
/// shares to correctly re-construct the polynomial.
pub fn recover_pri_poly<S: Scheme>(
    shares: &mut [PriShare<S>],
    t: usize,
) -> Result<PriPoly<S>, PolyError> {
    let x_y = xy_scalar(shares, t);
    if x_y.len() != t {
        return Err(PolyError::RecoverPriPolyNeedMoreShares);
    }
    let mut acc_poly = PriPoly {
        coeffs: Vec::with_capacity(t),
    };

    for (j, (_, y)) in &x_y {
        let mut basis = lagrange_basis::<S>(j, &x_y)?;

        for coeff in &mut basis.coeffs {
            *coeff *= y;
        }

        if !acc_poly.coeffs.is_empty() {
            acc_poly.add(basis)?;
        } else {
            acc_poly = basis
        }
    }

    Ok(acc_poly)
}

fn xy_scalar<S: Scheme>(shares: &mut [PriShare<S>], t: usize) -> ScalarsXY<S> {
    // sort shares: all participants needs to interpolate on the exact same order.
    shares.sort_by(|a, b| a.index.cmp(&b.index));

    let mut x_y: ScalarsXY<S> = BTreeMap::new();
    for s in shares {
        x_y.insert(s.index, (S::Scalar::from_u64(s.index as u64 + 1), s.value));
        if x_y.len() == t {
            break;
        }
    }

    x_y
}

/// Returns a PriPoly containing the Lagrange coefficients for the i-th position.
pub fn lagrange_basis<S: Scheme>(i: &u32, xs: &ScalarsXY<S>) -> Result<PriPoly<S>, PolyError> {
    let mut basis = PriPoly::<S> {
        coeffs: vec![S::Scalar::one()],
    };

    // compute lagrange basis l_j
    let mut acc = S::Scalar::one();
    for (m, (xm, _)) in xs {
        if i == m {
            continue;
        }
        basis = PriPoly::mul(&basis, &minus_const(*xm));
        // den = xi - xm
        let (mut den, _) = xs.get(i).ok_or(PolyError::LagrangeBasisXi)?;
        den -= xm;
        // den = 1 / den
        den = den
            .invert()
            .map_err(|_| PolyError::LagrangeBasisScalarIsNotInvertable)?;
        // acc = acc * den
        acc *= &den
    }

    // multiply all coefficients by the denominator
    for coef in &mut basis.coeffs {
        *coef *= &acc
    }

    Ok(basis)
}

fn minus_const<S: Scheme>(c: S::Scalar) -> PriPoly<S> {
    PriPoly {
        coeffs: vec![c.negate(), S::Scalar::one()],
    }
}

/// Reconstructs the secret commitment p(0) from a list of public
/// shares using Lagrange interpolation.
pub fn recover_commit<S: Scheme>(
    shares: &mut [PubShare<S>],
    t: u32,
) -> Result<KeyPoint<S>, PolyError> {
    let x_y = xy_commit(shares, t);
    if x_y.len() < t as usize {
        return Err(PolyError::RecoverCommitmentNeedMoreShares);
    }
    let mut acc = <<S as Scheme>::Key as Group>::Projective::identity();

    for (i, (xi, yi)) in &x_y {
        let mut num = S::Scalar::one();
        let mut den = S::Scalar::one();

        for (j, (mut xj, _)) in &x_y {
            if i == j {
                continue;
            }
            num *= &xj;
            xj -= xi;
            den *= &xj;
        }

        let inv = den
            .invert()
            .map_err(|_| PolyError::RecoverCommitmentScalarIsNotInvertable)?;
        num *= &inv;
        acc += &(num * yi);
    }

    Ok(acc.into())
}

fn xy_commit<S: Scheme>(shares: &mut [PubShare<S>], t: u32) -> CommitsXY<S> {
    // sort shares: all participants needs to interpolate on the exact same order.
    shares.sort_by(|a, b| a.i.cmp(&b.i));

    let mut x_y = BTreeMap::new();
    for s in shares {
        let _ = x_y.insert(s.i, (S::Scalar::from_u64(s.i as u64 + 1), s.v.clone()));
        if x_y.len() == t as usize {
            break;
        }
    }

    x_y
}

/// Reconstructs the shared secret p(0) from a list of private
/// shares using Lagrange interpolation.
pub fn recover_secret<S: Scheme>(
    shares: &mut [PriShare<S>],
    t: usize,
) -> Result<S::Scalar, PolyError> {
    let x_y = xy_scalar(shares, t);
    if x_y.len() < t {
        return Err(PolyError::RecoverSecretNeedMoreShares);
    }

    let mut acc = S::Scalar::zero();
    for (i, (xi, yi)) in &x_y {
        let mut num = yi.to_owned();
        let mut den = S::Scalar::one();
        for (j, (xj, _)) in &x_y {
            if i == j {
                continue;
            }
            let mut xj = *xj;
            num *= &xj;
            xj -= xi;
            den *= &xj;
        }
        let den = den
            .invert()
            .map_err(|_| PolyError::RecoverSecretScalarIsNotInvertable)?;
        num *= &den;
        acc += &num;
    }

    Ok(acc)
}

#[derive(Default, Clone, PartialEq)]
pub struct PubPoly<S: Scheme> {
    pub commits: Vec<KeyPoint<S>>,
}

#[derive(Debug, Default)]
pub struct PubShare<S: Scheme> {
    pub i: u32,
    pub v: KeyPoint<S>,
}

impl<S: Scheme> PubShare<S> {
    pub fn value(&self) -> &KeyPoint<S> {
        &self.v
    }
}

impl<S: Scheme> PubPoly<S> {
    /// Eval computes the public share v = p(i).
    pub fn eval(&self, i: u32) -> PubShare<S> {
        let xi = S::Scalar::from_u64((1 + i).into());
        let mut v = <S::Key as Group>::Projective::identity();
        for j in (0..self.threshold()).rev() {
            v *= &xi;
            v += &self.commits[j]
        }
        PubShare { i, v: v.into() }
    }

    /// Check a private share against a public commitment polynomial.
    pub fn check(&self, s: &PriShare<S>) -> bool {
        let pv = self.eval(s.index());
        let ps = S::sk_to_pk(s.value());

        *pv.value() == ps
    }

    /// Commit returns the secret commitment p(0), i.e., the constant term of the polynomial.
    pub fn commit(&self) -> Option<&KeyPoint<S>> {
        self.commits.first()
    }

    /// Threshold returns the secret sharing threshold.
    pub fn threshold(&self) -> usize {
        self.commits.len()
    }

    pub fn deserialize(raw_commits: &[Vec<u8>]) -> Result<Self, BackendsError> {
        let mut commits = Vec::with_capacity(raw_commits.len());

        for c in raw_commits {
            let point = Affine::deserialize(c)?;
            commits.push(point)
        }

        Ok(Self { commits })
    }
}
