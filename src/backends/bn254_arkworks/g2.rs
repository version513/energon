use super::super::error::BackendsError;
use super::super::error::BlsError;
use super::scalar::Scalar;

use crate::curves::bn254;
use crate::traits::Affine;
use crate::traits::Group;
use crate::traits::PairingCurve;
use crate::traits::Projective;

use ark_bn254 as ark_curve;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ec::PrimeGroup;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;

use std::fmt::Display;
use std::ops::AddAssign;
use std::ops::Mul;
use std::ops::MulAssign;

#[derive(Debug, Clone, Default)]
pub struct G2Affine(pub(super) ark_curve::G2Affine);

impl Affine for G2Affine {
    type Serialized = [u8; bn254::POINT_SIZE_G2];

    fn generator() -> Self {
        Self(ark_curve::G2Affine::generator())
    }

    fn serialize(&self) -> Result<Self::Serialized, BackendsError> {
        let mut bytes: Self::Serialized = [0; bn254::POINT_SIZE_G2];

        self.0
            .serialize_uncompressed(bytes.as_mut_slice())
            .map_err(|_| BackendsError::PointSerialize)?;

        bytes[..bn254::POINT_SIZE_G2 / 2].reverse();
        bytes[bn254::POINT_SIZE_G2 / 2..].reverse();

        Ok(bytes)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, BackendsError> {
        let mut bytes: [u8; bn254::POINT_SIZE_G2] =
            bytes.try_into().map_err(|_| BackendsError::PointInputLen)?;

        bytes[..bn254::POINT_SIZE_G2 / 2].reverse();
        bytes[bn254::POINT_SIZE_G2 / 2..].reverse();

        let point = CanonicalDeserialize::deserialize_uncompressed(bytes.as_slice())
            .map_err(|_| BackendsError::PointDeserialize)?;

        Ok(Self(point))
    }

    fn identity() -> Self {
        Self(ark_curve::G2Affine::identity())
    }

    fn is_on_curve(&self) -> bool {
        self.0.is_on_curve()
    }

    fn is_identity(&self) -> bool {
        self.0.is_zero()
    }
}

#[derive(Debug, Clone)]
pub struct G2Projective(pub(super) ark_curve::G2Projective);

impl Projective for G2Projective {
    type Serialized = [u8; bn254::POINT_SIZE_G2];

    fn generator() -> Self {
        Self(ark_curve::G2Projective::generator())
    }

    fn serialize(&self) -> Result<Self::Serialized, BackendsError> {
        let mut bytes: Self::Serialized = [0; bn254::POINT_SIZE_G2];

        self.0
            .serialize_uncompressed(bytes.as_mut_slice())
            .map_err(|_| BackendsError::PointSerialize)?;
        bytes[..bn254::POINT_SIZE_G2 / 2].reverse();
        bytes[bn254::POINT_SIZE_G2 / 2..].reverse();

        Ok(bytes)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, BackendsError> {
        let mut bytes: [u8; bn254::POINT_SIZE_G2] =
            bytes.try_into().map_err(|_| BackendsError::PointInputLen)?;

        bytes[..bn254::POINT_SIZE_G2 / 2].reverse();
        bytes[bn254::POINT_SIZE_G2 / 2..].reverse();
        let point = CanonicalDeserialize::deserialize_uncompressed(bytes.as_slice())
            .map_err(|_| BackendsError::PointDeserialize)?;

        Ok(Self(point))
    }

    fn identity() -> Self {
        G2Projective(ark_curve::G2Projective::default())
    }
}

impl PairingCurve for bn254::G2 {
    type Pair = <bn254::G1 as Group>::Affine;

    fn bls_verify(
        key: &<Self as Group>::Affine,
        sig: &Self::Pair,
        msg: &[u8],
    ) -> Result<(), BlsError> {
        if msg.is_empty() {
            return Err(BlsError::VerifyEmptyMessage)?;
        }
        let g = <Self as Group>::Affine::generator();
        let sig: ark_ec::bn::G1Prepared<ark_bn254::Config> = sig.0.into();
        let p: ark_ec::bn::G1Prepared<ark_bn254::Config> =
            super::hash_to_curve_on_g1::map_to_curve_svdw(msg).into();

        let lhs = ark_bn254::Bn254::pairing(sig, g.0);
        let rhs = ark_bn254::Bn254::pairing(p, key.0);

        if !lhs.eq(&rhs) {
            return Err(BlsError::InvalidSignature);
        }

        Ok(())
    }

    fn bls_sign(msg: &[u8], sk: &Self::Scalar) -> Result<Self::Pair, BlsError> {
        let point = super::hash_to_curve_on_g1::map_to_curve_svdw(msg);
        let p = (point * sk.0).into_affine();

        Ok(super::g1::G1Affine(p))
    }
}

impl Mul<&Scalar> for G2Affine {
    type Output = G2Projective;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        G2Projective(self.0 * rhs.0)
    }
}

impl Mul<Scalar> for G2Affine {
    type Output = G2Projective;

    fn mul(self, rhs: Scalar) -> Self::Output {
        G2Projective(self.0 * rhs.0)
    }
}

impl Mul<&G2Affine> for Scalar {
    type Output = G2Projective;

    fn mul(self, rhs: &G2Affine) -> Self::Output {
        G2Projective(rhs.0 * self.0)
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a G2Affine {
    type Output = G2Projective;

    fn mul(self, rhs: &'b Scalar) -> Self::Output {
        G2Projective(self.0 * rhs.0)
    }
}

impl From<&G2Projective> for G2Affine {
    fn from(p: &G2Projective) -> G2Affine {
        G2Affine(ark_curve::G2Affine::from(p.0))
    }
}

impl From<G2Projective> for G2Affine {
    fn from(p: G2Projective) -> G2Affine {
        G2Affine::from(&p)
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

impl From<&G2Affine> for G2Projective {
    fn from(p: &G2Affine) -> G2Projective {
        G2Projective(ark_curve::G2Projective::from(p.0))
    }
}

impl From<G2Affine> for G2Projective {
    fn from(p: G2Affine) -> G2Projective {
        G2Projective(ark_curve::G2Projective::from(p.0))
    }
}

impl Display for G2Affine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.serialize() {
            Ok(bytes) => {
                write!(f, "{}", hex::encode(bytes))
            }
            Err(err) => {
                write!(f, "Display: error serializing G2Affine: {err}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialization_check() {
        // Data from https://api.drand.sh/04f1e9062b8a81f848fded9c12306733282b2727ecced50032187751166ec8c3/info
        let mut bytes=hex::decode("07e1d1d335df83fa98462005690372c643340060d205306a9aa8106b6bd0b3820557ec32c2ad488e4d4f6008f89a346f18492092ccc0d594610de2732c8b808f0095685ae3a85ba243747b1b2f426049010f6b73a0cf1d389351d5aaaa1047f6297d3a4f9749b33eb2d904c9d9ebf17224150ddd7abd7567a9bec6c74480ee0b").unwrap();

        let affine_point = <G2Affine as Affine>::deserialize(&bytes).unwrap();
        let projective_point = <G2Projective as Projective>::deserialize(&bytes).unwrap();

        assert_eq!(affine_point.serialize().unwrap().as_ref(), bytes);
        assert_eq!(projective_point.serialize().unwrap().as_ref(), bytes);

        // invalid size
        bytes.push(1);

        assert_eq!(
            <G2Affine as Affine>::deserialize(&bytes),
            Err(BackendsError::PointInputLen)
        )
    }
}
