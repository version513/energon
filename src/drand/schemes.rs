use super::traits::BeaconDigest;
use super::traits::DrandScheme;

use crate::curves::bls12381;
use crate::curves::bn254;
use crate::traits::Group;
use crate::traits::Scheme;

use crypto_common::typenum::U32;
use crypto_common::OutputSizeUser;

use sha2::Digest;
use sha2::Sha256;
use sha3::Keccak256;

pub use bls12381_schemes::{DefaultScheme, SigsOnG1Scheme, UnchainedScheme};

macro_rules! impl_scheme {
    // Name of generic scheme type, e.g. for [`UnchainedScheme`] the next code is valid:
    //
    //   let key_base_point: KeyPoint<UnchainedScheme> = Affine::generator();
    // 
  ( name = $scheme_name:ident,
    // ID is a str scheme representation, used as metadata in protocol
    id = $scheme_id:expr,
    // Supported curves: [ bls12381, bn254 ]
    curve = $curve:ident,
    // The group used to create the keys
    key_group = $key:ident, 
    // The group used to create the signatures; it must always be different from the key_group,
    // for safety, this enforced at compile time due to [`Scheme`] trait structure
    sig_group = $sig:ident,
    // Chained: hashing the previous signature and the round number
    // Unchained: hashing the round number
    randomness = $randomness:ident,
    // Digest function for beacon
    beacon_hasher = $beacon_hasher:ident ) => {
            
        #[derive(Debug, Default, PartialEq)]
        pub struct $scheme_name;

        impl DrandScheme for $scheme_name {
            const ID: &'static str = $scheme_id;
            type Beacon = $randomness<$beacon_hasher>;
        }

        impl Scheme for $scheme_name {
            type Key = $curve::$key;
            type Sig = $curve::$sig;
            type Scalar = <$curve::G1 as Group>::Scalar;
        }
    };
}

#[cfg(any(feature = "bls12381_arkworks", feature = "bls12381_blstrs"))]
mod bls12381_schemes{
    use super::*;

    impl_scheme!(
        name = DefaultScheme,
        id = "pedersen-bls-chained",
        curve = bls12381,
        key_group = G1,
        sig_group = G2,
        randomness = Chained,
        beacon_hasher = Sha256
    );

    impl_scheme!(
        name = UnchainedScheme,
        id = "pedersen-bls-unchained",
        curve = bls12381,
        key_group = G1,
        sig_group = G2,
        randomness = Unchained,
        beacon_hasher = Sha256
    );

    impl_scheme!(
        name = SigsOnG1Scheme,
        id = "bls-unchained-g1-rfc9380",
        curve = bls12381,
        key_group = G2,
        sig_group = G1,
        randomness = Unchained,
        beacon_hasher = Sha256
    );

}

#[cfg(feature = "bn254_arkworks")]
impl_scheme!(
    name = BN254UnchainedOnG1Scheme,
    id = "bls-bn254-unchained-on-g1",
    curve = bn254,
    key_group = G2,
    sig_group = G1,
    randomness = Unchained,
    beacon_hasher = Keccak256
);

pub struct Chained<D: Digest> {
    _marker: std::marker::PhantomData<D>,
}

pub struct Unchained<D: Digest> {
    _marker: std::marker::PhantomData<D>,
}

impl<S, D> BeaconDigest<S> for Chained<D> 
where
    S: DrandScheme,
    D: Digest + OutputSizeUser<OutputSize = U32>
{
    fn digest(prev_sig: &[u8], round: u64) -> [u8; 32] {
        let mut h = D::new();
        h.update(prev_sig);
        h.update(round.to_be_bytes());
        h.finalize().into()     
    }

    fn is_chained() -> bool {
        true
    }
}

impl<S, D> BeaconDigest<S> for Unchained<D> 
where
    S: DrandScheme,
    D: Digest + OutputSizeUser<OutputSize = U32>
{
    fn digest(_prev_sig: &[u8], round: u64) -> [u8; 32] {
        let mut h = D::new();
        h.update(round.to_be_bytes());
        h.finalize().into()
    }

    fn is_chained() -> bool {
        false
    }
}