use super::super::error::BackendsError;
use crate::curves::bn254;
use crate::traits::ScalarField;

use ark_bn254::Fr;
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::One;
use ark_std::UniformRand;
use ark_std::Zero;

use std::fmt::Display;
use std::ops::Add;
use std::ops::AddAssign;
use std::ops::Mul;
use std::ops::MulAssign;
use std::ops::Neg;
use std::ops::SubAssign;

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;

#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub struct Scalar(pub(super) Fr);

impl ScalarField for Scalar {
    const SCALAR_SIZE: usize = bn254::SCALAR_SIZE;
    type Serialized = [u8; Self::SCALAR_SIZE];

    fn one() -> Self {
        Self(Fr::one())
    }

    fn random() -> Self {
        let mut rng = ChaChaRng::from_entropy();
        Self(Fr::rand(&mut rng))
    }

    fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        Self(<Fr as PrimeField>::from_be_bytes_mod_order(bytes))
    }

    fn to_bytes_be(self) -> Result<Self::Serialized, BackendsError> {
        let mut bytes = [0; Self::SCALAR_SIZE];
        CanonicalSerialize::serialize_compressed(&self.0, &mut bytes[..])
            .map_err(|_| BackendsError::ScalarSerialize)?;
        bytes.reverse();

        Ok(bytes)
    }

    fn from_bytes_be(bytes: &[u8]) -> Result<Self, BackendsError> {
        let mut bytes: [u8; Self::SCALAR_SIZE] = bytes
            .try_into()
            .map_err(|_| BackendsError::ScalarInputLen)?;
        bytes.reverse();
        let scalar = Fr::from_random_bytes(&bytes).ok_or(BackendsError::ScalarDeserialize)?;

        Ok(Self(scalar))
    }

    fn invert(&self) -> Result<Self, BackendsError> {
        let scalar = Field::inverse(&self.0).ok_or(BackendsError::ScalarNonInvertable)?;
        Ok(Self(scalar))
    }

    fn negate(self) -> Self {
        Self(self.0.neg())
    }

    fn zero() -> Self {
        Self(Fr::zero())
    }

    fn from_u64(val: u64) -> Self {
        Self(Fr::from(val))
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Scalar;

    #[inline]
    fn mul(self, rhs: &Scalar) -> Scalar {
        let mut out = self;
        out.0 *= rhs.0;
        out
    }
}

impl MulAssign<&Scalar> for Scalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &Scalar) {
        self.0 *= rhs.0
    }
}

impl Add<&Scalar> for Scalar {
    type Output = Scalar;

    #[inline]
    fn add(self, rhs: &Scalar) -> Scalar {
        let mut out = self;
        out.0 += rhs.0;
        out
    }
}

impl AddAssign<&Scalar> for Scalar {
    #[inline]
    fn add_assign(&mut self, rhs: &Scalar) {
        self.0.add_assign(rhs.0)
    }
}

impl SubAssign<&Scalar> for Scalar {
    #[inline]
    fn sub_assign(&mut self, rhs: &Scalar) {
        self.0 -= rhs.0;
    }
}

impl Display for Scalar {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.to_bytes_be() {
            Ok(bytes) => f.write_str(&hex::encode(&bytes)),
            Err(err) => {
                write!(f, "Display: error serializing scalar: {}", err)
            }
        }
    }
}
