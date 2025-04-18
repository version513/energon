use crate::backends::error::BackendsError;
use crate::traits::Affine;
use crate::traits::Group;
use crate::traits::Projective;
use crate::traits::ScalarField;
use crate::traits::Scheme;

use crate::points::KeyPoint;

#[derive(Default, PartialEq)]
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

#[derive(Debug, Default)]
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

#[derive(Default, Clone)]
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

    /// Commit returns the secret commitment p(0), i.e., the constant term of the polynomial.
    pub fn commit(&self) -> Option<&KeyPoint<S>> {
        self.commits.first()
    }

    /// Threshold returns the secret sharing threshold.
    pub fn threshold(&self) -> usize {
        self.commits.len()
    }

    pub fn deserialize(raw_commits: &Vec<Vec<u8>>) -> Result<Self, BackendsError> {
        let mut commits = Vec::with_capacity(raw_commits.len());

        for c in raw_commits {
            let point = Affine::deserialize(c)?;
            commits.push(point)
        }

        Ok(Self { commits })
    }
}
