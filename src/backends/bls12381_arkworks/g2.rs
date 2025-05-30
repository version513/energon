use super::super::error::BackendsError;
use super::super::error::BlsError;
use super::scalar::Scalar;
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
use ark_ec::PrimeGroup;
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;

use std::fmt::Display;
use std::ops::AddAssign;
use std::ops::Mul;
use std::ops::MulAssign;

use sha2::Sha256;

#[derive(Debug, Clone, Default)]
pub struct G2Affine(pub(super) ark_curve::G2Affine);

impl Affine for G2Affine {
    type Serialized = [u8; bls12381::POINT_SIZE_G2];

    fn generator() -> Self {
        Self(ark_curve::G2Affine::generator())
    }

    fn serialize(&self) -> Result<Self::Serialized, BackendsError> {
        let mut bytes: Self::Serialized = [0; bls12381::POINT_SIZE_G2];

        self.0
            .serialize_compressed(&mut bytes.as_mut_slice())
            .map_err(|_| BackendsError::PointSerialize)?;

        Ok(bytes)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, BackendsError> {
        let point = CanonicalDeserialize::deserialize_compressed(bytes)
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
    type Serialized = [u8; bls12381::POINT_SIZE_G2];

    fn generator() -> Self {
        Self(ark_curve::G2Projective::generator())
    }

    fn serialize(&self) -> Result<Self::Serialized, BackendsError> {
        let mut bytes: Self::Serialized = [0; bls12381::POINT_SIZE_G2];

        self.0
            .serialize_compressed(&mut bytes.as_mut_slice())
            .map_err(|_| BackendsError::PointSerialize)?;

        Ok(bytes)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, BackendsError> {
        let point = CanonicalDeserialize::deserialize_compressed(bytes)
            .map_err(|_| BackendsError::PointDeserialize)?;

        Ok(Self(point))
    }

    fn identity() -> Self {
        G2Projective(ark_curve::G2Projective::default())
    }
}

impl PairingCurve for bls12381::G2 {
    type Pair = <bls12381::G1 as Group>::Affine;

    fn bls_verify(
        key: &<Self as Group>::Affine,
        sig: &Self::Pair,
        msg: &[u8],
    ) -> Result<(), BlsError> {
        if msg.is_empty() {
            return Err(BlsError::VerifyEmptyMessage);
        }
        let g = <Self as Group>::Affine::generator();
        let hasher = MapToCurveBasedHasher::<
            ark_curve::G1Projective,
            DefaultFieldHasher<Sha256>,
            WBMap<ark_curve::g1::Config>,
        >::new(bls12381::G1::DST)
        .map_err(|_| BlsError::VerifyMapToCurveHasher)?;

        let p = hasher.hash(msg).map_err(|_| BlsError::VerifyMapToCurve)?;

        let p1 = Bls12_381::pairing(p, key.0);
        let p2 = Bls12_381::pairing(sig.0, g.0);
        if p1 != p2 {
            return Err(BlsError::InvalidSignature);
        }

        Ok(())
    }

    fn bls_sign(msg: &[u8], sk: &Self::Scalar) -> Result<Self::Pair, BlsError> {
        if msg.is_empty() {
            return Err(BlsError::SignEmptyMessage);
        }
        let hasher = MapToCurveBasedHasher::<
            ark_curve::G1Projective,
            DefaultFieldHasher<Sha256>,
            WBMap<ark_curve::g1::Config>,
        >::new(bls12381::G1::DST)
        .map_err(|_| BlsError::SignMapToCurveHasher)?;
        let h = hasher.hash(msg).map_err(|_| BlsError::SignMapToCurve)?;
        let p = (h * &sk.0).into_affine();

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
        let mut writer = Vec::new();
        match self.0.serialize_compressed(&mut writer) {
            Ok(_) => {
                write!(f, "{}", hex::encode(writer))
            }
            Err(err) => {
                write!(f, "Display: error serializing G2Affine: {}", err)
            }
        }
    }
}
