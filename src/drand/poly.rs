use super::scheme::Scheme;

use crate::traits::Affine;
use crate::traits::Group;
use crate::traits::PointError;
use crate::traits::Projective;
use crate::traits::ScalarField;

type PublicKey<S> = <<S as Scheme>::Key as Group>::Affine;

pub struct PriShare<S: Scheme> {
    pub i: u32,
    pub v: S::Scalar,
}

#[derive(Debug)]
pub struct PriPoly<S: Scheme> {
    coeffs: Vec<S::Scalar>,
}

impl<S: Scheme> PriPoly<S> {
    pub fn new(degree: u32) -> Self {
        let mut coeffs = Vec::new();
        for _ in 0..degree {
            coeffs.push(ScalarField::random())
        }

        Self { coeffs }
    }

    pub fn eval(&self, i: u32) -> PriShare<S> {
        let xi = S::Scalar::from_u64((1 + i).into());
        let mut v = S::Scalar::zero();
        for j in (0..self.threshold()).rev() {
            v *= &xi;
            v += &self.coeffs[j]
        }

        PriShare { i, v }
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

pub struct PubPoly<S: Scheme> {
    pub commits: Vec<PublicKey<S>>,
}

#[derive(Debug)]
pub struct PubShare<S: Scheme> {
    pub i: u32,
    pub v: PublicKey<S>,
}

impl<S: Scheme> PubShare<S> {
    pub fn value(&self) -> &PublicKey<S> {
        &self.v
    }
}

impl<S: Scheme> PubPoly<S> {
    pub fn eval(&self, i: u32) -> PubShare<S> {
        let xi = S::Scalar::from_u64((1 + i).into());
        let mut v = <S::Key as Group>::Projective::identity();
        for j in (0..self.threshold()).rev() {
            v *= &xi;
            v += &self.commits[j]
        }
        PubShare { i, v: v.into() }
    }

    pub fn threshold(&self) -> usize {
        self.commits.len()
    }

    pub fn deserialize(raw_commits: &Vec<Vec<u8>>) -> Result<Self, PointError> {
        let mut commits = Vec::with_capacity(raw_commits.len());

        for c in raw_commits {
            let point = Affine::deserialize(c)?;
            commits.push(point)
        }

        Ok(Self { commits })
    }
}
