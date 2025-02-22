use super::super::error::BackendsError;
use super::super::error::BlsError;
use super::scalar::Scalar;

use crate::curves::bn254;
use crate::traits::Affine;
use crate::traits::Group;
use crate::traits::PairingCurve;
use crate::traits::Projective;

use ark_bn254 as ark_curve;
use ark_ec::AffineRepr;
use ark_ec::PrimeGroup;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;

use std::fmt::Display;
use std::ops::AddAssign;
use std::ops::Mul;
use std::ops::MulAssign;

#[derive(Debug, Clone, Default)]
pub struct G1Affine(pub(super) ark_curve::G1Affine);

impl Affine for G1Affine {
    type Serialized = [u8; bn254::POINT_SIZE_G1];

    fn generator() -> Self {
        Self(ark_curve::G1Affine::generator())
    }

    fn serialize(&self) -> Result<Self::Serialized, BackendsError> {
        let mut bytes: Self::Serialized = [0; bn254::POINT_SIZE_G1];

        self.0
            .serialize_uncompressed(&mut bytes.as_mut_slice())
            .map_err(|_| BackendsError::PointSerialize)?;

        bytes[..bn254::POINT_SIZE_G1 / 2].reverse();
        bytes[bn254::POINT_SIZE_G1 / 2..].reverse();

        Ok(bytes)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, BackendsError> {
        let mut bytes: [u8; bn254::POINT_SIZE_G1] =
            bytes.try_into().map_err(|_| BackendsError::PointInputLen)?;

        bytes[..bn254::POINT_SIZE_G1 / 2].reverse();
        bytes[bn254::POINT_SIZE_G1 / 2..].reverse();

        let point = CanonicalDeserialize::deserialize_uncompressed(bytes.as_slice())
            .map_err(|_| BackendsError::PointDeserialize)?;

        Ok(Self(point))
    }

    fn identity() -> Self {
        Self(ark_curve::G1Affine::identity())
    }

    fn is_on_curve(&self) -> bool {
        self.0.is_on_curve()
    }

    fn is_identity(&self) -> bool {
        self.0.is_zero()
    }
}

#[derive(Debug, Clone)]
pub struct G1Projective(pub(super) ark_curve::G1Projective);

impl Projective for G1Projective {
    type Serialized = [u8; bn254::POINT_SIZE_G1];

    fn generator() -> Self {
        Self(ark_curve::G1Projective::generator())
    }

    fn serialize(&self) -> Result<Self::Serialized, BackendsError> {
        let mut bytes: Self::Serialized = [0; bn254::POINT_SIZE_G1];

        self.0
            .serialize_uncompressed(&mut bytes.as_mut_slice())
            .map_err(|_| BackendsError::PointSerialize)?;

        bytes[..bn254::POINT_SIZE_G1 / 2].reverse();
        bytes[bn254::POINT_SIZE_G1 / 2..].reverse();

        Ok(bytes)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, BackendsError> {
        let mut bytes: [u8; bn254::POINT_SIZE_G1] =
            bytes.try_into().map_err(|_| BackendsError::PointInputLen)?;

        bytes[..bn254::POINT_SIZE_G1 / 2].reverse();
        bytes[bn254::POINT_SIZE_G1 / 2..].reverse();

        let point = CanonicalDeserialize::deserialize_uncompressed(bytes.as_slice())
            .map_err(|_| BackendsError::PointDeserialize)?;

        Ok(Self(point))
    }

    fn identity() -> Self {
        G1Projective(ark_curve::G1Projective::default())
    }
}

impl PairingCurve for bn254::G1 {
    type Pair = <bn254::G2 as Group>::Affine;

    // Signatures on G2 will most likely not be implemented (they are practically unused).
    fn bls_verify(
        _key: &<Self as Group>::Affine,
        _sig: &Self::Pair,
        _msg: &[u8],
    ) -> Result<(), BlsError> {
        unimplemented!()
    }

    fn bls_sign(_msg: &[u8], _sk: &Self::Scalar) -> Result<Self::Pair, BlsError> {
        unimplemented!()
    }
}

impl Mul<&Scalar> for &G1Affine {
    type Output = G1Projective;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        G1Projective(self.0 * rhs.0)
    }
}

impl Mul<&Scalar> for G1Affine {
    type Output = G1Projective;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        G1Projective(self.0 * rhs.0)
    }
}

impl Mul<Scalar> for G1Affine {
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

impl From<&G1Projective> for G1Affine {
    fn from(p: &G1Projective) -> G1Affine {
        G1Affine(ark_curve::G1Affine::from(p.0))
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
        G1Projective(ark_curve::G1Projective::from(p.0))
    }
}

impl From<G1Affine> for G1Projective {
    fn from(p: G1Affine) -> G1Projective {
        G1Projective(ark_curve::G1Projective::from(p.0))
    }
}

impl Display for G1Affine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.serialize() {
            Ok(bytes) => {
                write!(f, "{}", hex::encode(bytes))
            }
            Err(err) => {
                write!(f, "Display: error serializing G1Affine: {err}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialization_check() {
        // Data from https://api.drand.sh/04f1e9062b8a81f848fded9c12306733282b2727ecced50032187751166ec8c3/public/513
        let mut bytes=hex::decode("06ded8c05af23042a0caf9b404c6140f9ec64adbaf82f04d5c37153e8412ed580f827c7d5ac7d02ca0bbd989d07594729bdcde7d6dc1001191c59dc9033d31b2").unwrap();

        let affine_point = <G1Affine as Affine>::deserialize(&bytes).unwrap();
        let projective_point = <G1Projective as Projective>::deserialize(&bytes).unwrap();

        assert_eq!(affine_point.serialize().unwrap().as_ref(), bytes);
        assert_eq!(projective_point.serialize().unwrap().as_ref(), bytes);

        // invalid size
        bytes.push(1);

        assert_eq!(
            <G1Affine as Affine>::deserialize(&bytes),
            Err(BackendsError::PointInputLen)
        )
    }
}
