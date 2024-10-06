use super::scalar::Scalar;
use crate::backends::error::BlsError;
use crate::backends::error::PointError;
use crate::curves::bls12381;
use crate::traits::Affine;
use crate::traits::Group;
use crate::traits::PairingCurve;
use crate::traits::Projective;

use ark_bls12_381 as ark_curve;
use ark_bls12_381::Bls12_381;
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
use ark_ec::hashing::HashToCurve;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ec::Group as _;
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;

use std::fmt::Display;
use std::ops::AddAssign;
use std::ops::Mul;
use std::ops::MulAssign;

use sha2::Sha256;

#[derive(Debug, Clone)]
pub struct G1Affine(pub(super) ark_curve::G1Affine);

impl Affine for G1Affine {
    fn generator() -> Self {
        Self(ark_curve::G1Affine::generator())
    }

    fn serialize(&self) -> Result<Vec<u8>, PointError> {
        let mut bytes = Vec::new();
        self.0
            .serialize_compressed(&mut bytes)
            .map_err(|e| PointError::Serialization(e.to_string()))?;

        Ok(bytes)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, PointError> {
        let point = CanonicalDeserialize::deserialize_compressed(bytes)
            .map_err(|e| PointError::Serialization(e.to_string()))?;

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
    fn generator() -> Self {
        Self(ark_curve::G1Projective::generator())
    }

    fn serialize(&self) -> Result<Vec<u8>, PointError> {
        let mut bytes = Vec::new();
        self.0
            .serialize_compressed(&mut bytes)
            .map_err(|e| PointError::Serialization(e.to_string()))?;

        Ok(bytes)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, PointError> {
        let point = CanonicalDeserialize::deserialize_compressed(bytes)
            .map_err(|e| PointError::Serialization(e.to_string()))?;

        Ok(Self(point))
    }

    fn identity() -> Self {
        G1Projective(ark_curve::G1Projective::default())
    }
}

impl PairingCurve for bls12381::G1 {
    type Pair = <bls12381::G2 as Group>::Affine;

    fn bls_verify(
        key: &<Self as Group>::Affine,
        sig: &Self::Pair,
        msg: &[u8],
    ) -> Result<(), BlsError> {
        if msg.is_empty() {
            return Err(BlsError::EmptyMessage);
        }
        let g = <Self as Group>::Affine::generator();
        let hasher = MapToCurveBasedHasher::<
            ark_curve::G2Projective,
            DefaultFieldHasher<Sha256>,
            WBMap<ark_curve::g2::Config>,
        >::new(bls12381::G2::DST)
        .map_err(|err| BlsError::HashToCurve(err.to_string()))?;

        let p = hasher
            .hash(msg)
            .map_err(|err| BlsError::HashToCurve(err.to_string()))?;

        let p1 = Bls12_381::pairing(key.0, p);
        let p2 = Bls12_381::pairing(g.0, sig.0);
        if p1 != p2 {
            return Err(BlsError::FailedVerification);
        }

        Ok(())
    }

    fn bls_sign(msg: &[u8], sk: &Self::Scalar) -> Result<Self::Pair, BlsError> {
        if msg.is_empty() {
            return Err(BlsError::EmptyMessage);
        }
        let hasher = MapToCurveBasedHasher::<
            ark_curve::G2Projective,
            DefaultFieldHasher<Sha256>,
            WBMap<ark_curve::g2::Config>,
        >::new(bls12381::G2::DST)
        .map_err(|err| BlsError::HashToCurve(err.to_string()))?;

        let h = hasher
            .hash(msg)
            .map_err(|err| BlsError::HashToCurve(err.to_string()))?;

        let p = (h * sk.0).into_affine();

        match p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve() && !p.is_zero() {
            true => Ok(super::g2::G2Affine(p)),
            false => Err(BlsError::Failed),
        }
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
        let mut writer = Vec::new();

        match self.0.serialize_compressed(&mut writer) {
            Ok(()) => {
                write!(f, "{}", hex::encode(writer))
            }
            Err(err) => {
                write!(f, "Display: error serializing G1Affine: {}", err)
            }
        }
    }
}
