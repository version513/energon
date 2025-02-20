use super::super::error::BackendsError;
use crate::curves::bls12381;
use crate::traits::ScalarField;

use std::fmt::Display;
use std::ops::Add;
use std::ops::AddAssign;
use std::ops::Mul;
use std::ops::MulAssign;
use std::ops::SubAssign;

use core::fmt;
use group::ff::Field;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;

#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub struct Scalar(pub(super) blstrs::Scalar);

impl ScalarField for Scalar {
    const SCALAR_SIZE: usize = bls12381::SCALAR_SIZE;

    fn one() -> Self {
        Self(blstrs::Scalar::ONE)
    }

    fn random() -> Self {
        let mut rng = ChaChaRng::from_entropy();
        Self(blstrs::Scalar::random(&mut rng))
    }

    // FIXME: check conditions if None is ever possible
    fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        let mut sk = blst_lib::blst_scalar::default();

        unsafe {
            let _ = blst_lib::blst_scalar_from_be_bytes(&mut sk, bytes.as_ptr(), bytes.len());
        }

        match blstrs::Scalar::from_bytes_le(&sk.b).into_option() {
            Some(sk) => Self(sk),
            None => Self(blstrs::Scalar::ONE),
        }
    }

    fn to_bytes_be(self) -> Result<[u8; Self::SCALAR_SIZE], BackendsError> {
        Ok(self.0.to_bytes_be())
    }

    fn from_bytes_be(bytes: &[u8]) -> Result<Self, BackendsError> {
        let bytes: [u8; Self::SCALAR_SIZE] = bytes
            .try_into()
            .map_err(|_| BackendsError::ScalarInputLen)?;

        let scalar = blstrs::Scalar::from_bytes_be(&bytes)
            .into_option()
            .ok_or_else(|| BackendsError::ScalarDeserialize)?;

        Ok(Self(scalar))
    }

    fn from_u64(val: u64) -> Self {
        let limbs: [u64; 4] = [val, 0, 0, 0];
        let mut out = blst_lib::blst_fr::default();

        unsafe { blst_lib::blst_fr_from_uint64(&mut out, limbs.as_ptr()) };

        Self(blstrs::Scalar::from(out))
    }

    fn invert(&self) -> Result<Self, BackendsError> {
        let scalar = self
            .0
            .invert()
            .into_option()
            .ok_or_else(|| BackendsError::ScalarNonInvertable)?;

        Ok(Self(scalar))
    }

    fn zero() -> Self {
        Self(blstrs::Scalar::ZERO)
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

impl Add<&Scalar> for Scalar {
    type Output = Scalar;

    #[inline]
    fn add(self, rhs: &Scalar) -> Scalar {
        let mut out = self;
        out.0 += rhs.0;
        out
    }
}

impl MulAssign<&Scalar> for Scalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &Scalar) {
        self.0 *= rhs.0;
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &hex::encode(self.0.to_bytes_be()))
    }
}
