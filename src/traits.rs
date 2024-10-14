use crate::backends::BlsError;
use crate::backends::PointError;
use crate::backends::ScalarError;

use std::fmt::Debug;
use std::fmt::Display;
use std::ops::Add;
use std::ops::AddAssign;
use std::ops::Mul;
use std::ops::MulAssign;
use std::ops::SubAssign;

use crev_common::Blake2b256;
use sha2::digest::Digest;

pub trait Group: Sized {
    const DST: &'static [u8];
    const POINT_SIZE: usize;

    type Affine: Affine
        + Clone
        + From<Self::Projective>
        + Into<Self::Projective>
        + PartialEq
        + for<'a> Mul<&'a Self::Scalar, Output = Self::Projective>
        + Mul<Self::Scalar, Output = Self::Projective>;

    type Projective: Projective
        + Clone
        + From<Self::Affine>
        + Into<Self::Affine>
        + for<'a> From<&'a Self::Affine>
        + for<'a> MulAssign<&'a Self::Scalar>
        + for<'a> AddAssign<&'a Self::Affine>
        + for<'a> AddAssign<&'a Self::Projective>;

    type Scalar: ScalarField + for<'a> Mul<&'a Self::Affine, Output = Self::Projective>;
}

pub trait ScalarField:
    Sync
    + Send
    + Sized
    + Debug
    + PartialEq
    + Copy
    + Display
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> MulAssign<&'a Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> SubAssign<&'a Self>
    + for<'a> AddAssign<&'a Self>
{
    const SCALAR_SIZE: usize;

    fn zero() -> Self;
    fn one() -> Self;
    fn random() -> Self;
    fn invert(&self) -> Result<Self, ScalarError>;
    fn from_u64(val: u64) -> Self;
    fn to_bytes_be(self) -> Result<[u8; 32], ScalarError>;
    fn from_bytes_be(bytes: &[u8]) -> Result<Self, ScalarError>;
    fn from_be_bytes_mod_order(bytes: &[u8]) -> Self;
    fn set_bytes(public: &[u8], r: &[u8], msg: &[u8]) -> Self {
        let mut h = sha2::Sha512::new();
        h.update(r);
        h.update(public);
        h.update(msg);

        Self::from_be_bytes_mod_order(h.finalize().as_slice())
    }
}

pub trait Affine: Sync + Send + Sized + PartialEq + Debug + Display {
    fn generator() -> Self;
    fn identity() -> Self;
    fn is_on_curve(&self) -> bool;
    fn is_identity(&self) -> bool;
    fn serialize(&self) -> Result<Vec<u8>, PointError>;
    fn deserialize(bytes: &[u8]) -> Result<Self, PointError>;
    fn hash(&self) -> Result<Vec<u8>, PointError> {
        let mut hasher = Blake2b256::new();
        hasher.update(self.serialize()?);

        Ok(hasher.finalize().to_vec())
    }
}

pub trait Projective: Sized + Debug + PartialEq + for<'a> AddAssign<&'a Self> {
    fn identity() -> Self;
    fn generator() -> Self;
    fn serialize(&self) -> Result<Vec<u8>, PointError>;
    fn deserialize(bytes: &[u8]) -> Result<Self, PointError>;
    fn hash(&self) -> Result<Vec<u8>, PointError> {
        let mut hasher = Blake2b256::new();
        hasher.update(&self.serialize()?);

        Ok(hasher.finalize().to_vec())
    }
}

pub trait PairingCurve: Group {
    type Pair: Affine;

    fn bls_sign(msg: &[u8], sk: &Self::Scalar) -> Result<Self::Pair, BlsError>;
    fn bls_verify(key: &Self::Affine, sig: &Self::Pair, msg: &[u8]) -> Result<(), BlsError>;
}

pub trait Scheme {
    type Key: Group<Scalar = Self::Scalar>
        + PairingCurve<Scalar = Self::Scalar, Pair = <Self::Sig as Group>::Affine>;

    type Sig: Group<Scalar = Self::Scalar>;

    type Scalar: ScalarField
        + for<'a> Mul<&'a <Self::Key as Group>::Affine, Output = <Self::Key as Group>::Projective>;

    fn sk_to_pk(sk: &Self::Scalar) -> <Self::Key as Group>::Affine {
        (<Self::Key as Group>::Affine::generator() * sk).into()
    }
}
