use super::super::error::BackendsError;
use super::super::error::BlsError;
use super::bls12381;
use super::scalar::Scalar;
use super::Serializer;

use crate::traits::Affine;
use crate::traits::Group;
use crate::traits::PairingCurve;
use crate::traits::Projective;

use core::fmt;
use group::prime::PrimeCurveAffine as _;
use group::Group as _;
use pairing::MillerLoopResult;
use pairing::MultiMillerLoop;
use std::ops::AddAssign;
use std::ops::Mul;
use std::ops::MulAssign;
use std::ops::Neg;

#[derive(Debug, Clone, Default)]
pub struct G1Affine(pub(super) blstrs::G1Affine);

impl Affine for G1Affine {
    type Serialized = [u8; bls12381::POINT_SIZE_G1];

    fn generator() -> Self {
        Self(blstrs::G1Affine::generator())
    }

    fn serialize(&self) -> Result<Self::Serialized, BackendsError> {
        let output = Serializer::serialize(self)?;

        Ok(output)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, BackendsError> {
        let bytes: &[u8; bls12381::G1::POINT_SIZE] =
            &bytes.try_into().map_err(|_| BackendsError::PointInputLen)?;

        let point = blstrs::G1Affine::from_compressed(bytes)
            .into_option()
            .ok_or(BackendsError::PointDeserialize)?;

        Ok(Self(point))
    }

    fn is_on_curve(&self) -> bool {
        self.0.is_on_curve().into()
    }

    fn is_identity(&self) -> bool {
        self.0.is_identity().into()
    }

    fn identity() -> Self {
        Self(blstrs::G1Affine::identity())
    }
}

#[derive(Debug, Clone)]
pub struct G1Projective(pub(super) blstrs::G1Projective);

impl Projective for G1Projective {
    type Serialized = [u8; bls12381::POINT_SIZE_G1];

    fn generator() -> Self {
        Self(blstrs::G1Projective::generator())
    }

    fn serialize(&self) -> Result<Self::Serialized, BackendsError> {
        let output = Serializer::serialize(self)?;

        Ok(output)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, BackendsError> {
        let bytes: &[u8; bls12381::G1::POINT_SIZE] =
            &bytes.try_into().map_err(|_| BackendsError::PointInputLen)?;

        let point = blstrs::G1Projective::from_compressed(bytes)
            .into_option()
            .ok_or(BackendsError::PointDeserialize)?;

        Ok(Self(point))
    }

    fn identity() -> Self {
        G1Projective(blstrs::G1Projective::identity())
    }
}

impl PairingCurve for bls12381::G1 {
    type Pair = <bls12381::G2 as Group>::Affine;

    fn bls_sign(msg: &[u8], sk: &Self::Scalar) -> Result<Self::Pair, BlsError> {
        if msg.is_empty() {
            return Err(BlsError::SignEmptyMessage);
        }
        let p = blstrs::G2Projective::hash_to_curve(msg, bls12381::G2::DST, &[]);
        let mut sig = blstrs::G2Affine::default();
        unsafe {
            blst_lib::blst_sign_pk2_in_g1(
                std::ptr::null_mut(),
                sig.as_mut(),
                p.as_ref(),
                &sk.0.into(),
            );
        }

        Ok(super::g2::G2Affine(sig))
    }

    fn bls_verify(
        key: &<Self as Group>::Affine,
        sig: &Self::Pair,
        msg: &[u8],
    ) -> Result<(), BlsError> {
        if msg.is_empty() {
            return Err(BlsError::VerifyEmptyMessage);
        }
        let msg: blstrs::G2Affine =
            blstrs::G2Projective::hash_to_curve(msg, bls12381::G2::DST, &[]).into();
        let g = blstrs::G1Affine::generator();
        let p1 = (&key.0.neg(), &blstrs::G2Prepared::from(msg));
        let p2 = (&g, &blstrs::G2Prepared::from(sig.0));

        if blstrs::Bls12::multi_miller_loop(&[p1, p2])
            .final_exponentiation()
            .is_identity()
            .unwrap_u8()
            != 1
        {
            return Err(BlsError::InvalidSignature);
        }

        Ok(())
    }
}

impl Serializer for G1Affine {
    type Output = <G1Affine as Affine>::Serialized;

    #[inline(always)]
    fn serialize(&self) -> Result<Self::Output, std::convert::Infallible> {
        Ok(self.0.to_compressed())
    }
}

impl Serializer for G1Projective {
    type Output = <G1Projective as Projective>::Serialized;

    #[inline(always)]
    fn serialize(&self) -> Result<Self::Output, std::convert::Infallible> {
        Ok(self.0.to_compressed())
    }
}

impl Mul<&Scalar> for G1Affine {
    type Output = G1Projective;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        G1Projective(self.0.mul(&rhs.0))
    }
}

impl Mul<&Scalar> for &G1Affine {
    type Output = G1Projective;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        G1Projective(self.0 * rhs.0)
    }
}

impl Mul<&G1Affine> for &Scalar {
    type Output = G1Projective;

    fn mul(self, rhs: &G1Affine) -> Self::Output {
        G1Projective(rhs.0 * self.0)
    }
}

impl Mul<Scalar> for &G1Affine {
    type Output = G1Projective;

    fn mul(self, rhs: Scalar) -> Self::Output {
        G1Projective(self.0 * rhs.0)
    }
}

impl Mul<&G1Affine> for Scalar {
    type Output = G1Projective;

    fn mul(self, rhs: &G1Affine) -> Self::Output {
        G1Projective(rhs.0 * self.0)
    }
}

impl Mul<Scalar> for G1Affine {
    type Output = G1Projective;

    fn mul(self, rhs: Scalar) -> Self::Output {
        G1Projective(self.0 * rhs.0)
    }
}

impl From<&G1Projective> for G1Affine {
    fn from(p: &G1Projective) -> G1Affine {
        G1Affine(blstrs::G1Affine::from(p.0))
    }
}

impl From<G1Projective> for G1Affine {
    fn from(p: G1Projective) -> G1Affine {
        G1Affine::from(&p)
    }
}

impl PartialEq for G1Affine {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl fmt::Display for G1Affine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &hex::encode(self.0.to_compressed()))
    }
}

impl MulAssign<&Scalar> for G1Projective {
    #[inline]
    fn mul_assign(&mut self, rhs: &Scalar) {
        self.0 *= rhs.0;
    }
}

impl AddAssign<&G1Affine> for G1Projective {
    #[inline]
    fn add_assign(&mut self, rhs: &G1Affine) {
        self.0 += rhs.0;
    }
}

impl AddAssign<&G1Projective> for G1Projective {
    #[inline]
    fn add_assign(&mut self, rhs: &G1Projective) {
        self.0 += rhs.0;
    }
}

impl PartialEq for G1Projective {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl From<&G1Affine> for G1Projective {
    fn from(p: &G1Affine) -> G1Projective {
        G1Projective(blstrs::G1Projective::from(p.0))
    }
}

impl From<G1Affine> for G1Projective {
    fn from(p: G1Affine) -> G1Projective {
        G1Projective(blstrs::G1Projective::from(p.0))
    }
}

impl MulAssign<&Scalar> for G1Affine {
    #[inline]
    fn mul_assign(&mut self, rhs: &Scalar) {
        self.0 *= rhs.0;
    }
}
