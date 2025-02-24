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
pub struct G2Affine(pub(super) blstrs::G2Affine);

impl Affine for G2Affine {
    type Serialized = [u8; bls12381::POINT_SIZE_G2];

    fn generator() -> Self {
        Self(blstrs::G2Affine::generator())
    }

    fn serialize(&self) -> Result<Self::Serialized, BackendsError> {
        let output = Serializer::serialize(self)?;

        Ok(output)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, BackendsError> {
        let bytes: &[u8; bls12381::G2::POINT_SIZE] =
            &bytes.try_into().map_err(|_| BackendsError::PointInputLen)?;

        let point = blstrs::G2Affine::from_compressed(&bytes)
            .into_option()
            .ok_or_else(|| BackendsError::PointDeserialize)?;

        Ok(Self(point))
    }

    fn is_on_curve(&self) -> bool {
        self.0.is_on_curve().into()
    }

    fn is_identity(&self) -> bool {
        self.0.is_identity().into()
    }

    fn identity() -> Self {
        Self(blstrs::G2Affine::identity())
    }
}

#[derive(Debug, Clone)]
pub struct G2Projective(pub(super) blstrs::G2Projective);

impl Projective for G2Projective {
    type Serialized = [u8; bls12381::POINT_SIZE_G2];

    fn generator() -> Self {
        Self(blstrs::G2Projective::generator())
    }

    fn serialize(&self) -> Result<Self::Serialized, BackendsError> {
        let output = Serializer::serialize(self)?;

        Ok(output)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, BackendsError> {
        let bytes: &[u8; bls12381::G2::POINT_SIZE] =
            &bytes.try_into().map_err(|_| BackendsError::PointInputLen)?;

        let point = blstrs::G2Projective::from_compressed(&bytes)
            .into_option()
            .ok_or_else(|| BackendsError::PointDeserialize)?;

        Ok(Self(point))
    }

    fn identity() -> Self {
        G2Projective(blstrs::G2Projective::identity())
    }
}

impl PairingCurve for bls12381::G2 {
    type Pair = <bls12381::G1 as Group>::Affine;

    fn bls_sign(msg: &[u8], sk: &<bls12381::G1 as Group>::Scalar) -> Result<Self::Pair, BlsError> {
        let p = blstrs::G1Projective::hash_to_curve(msg, bls12381::G1::DST, &[]);
        let mut sig = blstrs::G1Affine::default();
        unsafe {
            blst_lib::blst_sign_pk2_in_g2(
                std::ptr::null_mut(),
                sig.as_mut(),
                p.as_ref(),
                &sk.0.into(),
            );
        };

        Ok(super::g1::G1Affine(sig))
    }

    fn bls_verify(
        key: &<Self as Group>::Affine,
        sig: &Self::Pair,
        msg: &[u8],
    ) -> Result<(), BlsError> {
        let msg: blstrs::G1Affine =
            blstrs::G1Projective::hash_to_curve(msg, bls12381::G1::DST, &[]).into();
        let g = blstrs::G2Affine::generator();
        let p1 = (&msg, &blstrs::G2Prepared::from(key.0.neg()));
        let p2 = (&sig.0, &blstrs::G2Prepared::from(g));

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

impl Serializer for G2Affine {
    type Output = <G2Affine as Affine>::Serialized;

    #[inline(always)]
    fn serialize(&self) -> Result<Self::Output, std::convert::Infallible> {
        Ok(self.0.to_compressed())
    }
}

impl Serializer for G2Projective {
    type Output = <G2Projective as Projective>::Serialized;

    #[inline(always)]
    fn serialize(&self) -> Result<Self::Output, std::convert::Infallible> {
        Ok(self.0.to_compressed())
    }
}

impl Mul<&Scalar> for G2Affine {
    type Output = G2Projective;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        G2Projective(self.0.mul(&rhs.0))
    }
}

impl From<&G2Projective> for G2Affine {
    fn from(p: &G2Projective) -> G2Affine {
        G2Affine(blstrs::G2Affine::from(p.0))
    }
}

impl From<G2Projective> for G2Affine {
    fn from(p: G2Projective) -> G2Affine {
        G2Affine::from(&p)
    }
}

impl From<&G2Affine> for G2Projective {
    fn from(p: &G2Affine) -> G2Projective {
        G2Projective(blstrs::G2Projective::from(p.0))
    }
}

impl PartialEq for G2Affine {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl MulAssign<&Scalar> for G2Projective {
    #[inline]
    fn mul_assign(&mut self, rhs: &Scalar) {
        self.0 *= rhs.0;
    }
}

impl MulAssign<&Scalar> for G2Affine {
    #[inline]
    fn mul_assign(&mut self, rhs: &Scalar) {
        self.0 *= rhs.0;
    }
}

impl AddAssign<&G2Projective> for G2Projective {
    #[inline]
    fn add_assign(&mut self, rhs: &G2Projective) {
        self.0 += rhs.0;
    }
}

impl AddAssign<&G2Affine> for G2Projective {
    #[inline]
    fn add_assign(&mut self, rhs: &G2Affine) {
        self.0 += rhs.0;
    }
}

impl PartialEq for G2Projective {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl Mul<&Scalar> for &G2Affine {
    type Output = G2Projective;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        G2Projective(self.0 * rhs.0)
    }
}

impl Mul<&G2Affine> for &Scalar {
    type Output = G2Projective;

    fn mul(self, rhs: &G2Affine) -> Self::Output {
        G2Projective(rhs.0 * self.0)
    }
}

impl Mul<&G2Affine> for Scalar {
    type Output = G2Projective;

    fn mul(self, rhs: &G2Affine) -> Self::Output {
        G2Projective(rhs.0 * self.0)
    }
}

impl Mul<Scalar> for G2Affine {
    type Output = G2Projective;

    fn mul(self, rhs: Scalar) -> Self::Output {
        G2Projective(self.0 * rhs.0)
    }
}

impl Mul<Scalar> for &G2Affine {
    type Output = G2Projective;

    fn mul(self, rhs: Scalar) -> Self::Output {
        G2Projective(self.0 * rhs.0)
    }
}

impl From<G2Affine> for G2Projective {
    fn from(p: G2Affine) -> G2Projective {
        G2Projective(blstrs::G2Projective::from(p.0))
    }
}

impl fmt::Display for G2Affine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &hex::encode(self.0.to_compressed()))
    }
}
