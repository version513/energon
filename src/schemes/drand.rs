use crate::traits::Group;
use crate::traits::PairingCurve;
use crate::traits::Scheme;

use crate::cyber::ecies;
use crate::cyber::poly::PriShare;
use crate::cyber::poly::PubPoly;
use crate::cyber::schnorr;
use crate::cyber::tbls;
use crate::cyber::tbls::SigShare;

use crate::points::KeyPoint;
use crate::points::SigPoint;

pub trait DrandScheme: Scheme + 'static + Sized + PartialEq {
    const ID: &'static str;
    type Beacon: BeaconDigest<Self>;

    fn bls_sign(msg: &[u8], sk: &<Self as Scheme>::Scalar) -> Result<SigPoint<Self>, SchemeError> {
        <<Self as Scheme>::Key as PairingCurve>::bls_sign(msg, sk).map_err(SchemeError::Bls)
    }

    fn bls_verify(
        key: &KeyPoint<Self>,
        sig: &SigPoint<Self>,
        msg: &[u8],
    ) -> Result<(), SchemeError> {
        <<Self as Scheme>::Key as PairingCurve>::bls_verify(key, sig, msg).map_err(SchemeError::Bls)
    }

    fn schnorr_sign(
        private: &<Self as Scheme>::Scalar,
        msg: &[u8],
    ) -> Result<Vec<u8>, SchemeError> {
        schnorr::sign::<Self>(private, msg).map_err(SchemeError::Schnorr)
    }

    fn schnorr_verify(public: &KeyPoint<Self>, msg: &[u8], sig: &[u8]) -> Result<(), SchemeError> {
        schnorr::verify::<Self>(public, msg, sig).map_err(SchemeError::Schnorr)
    }

    fn encrypt(
        public: &KeyPoint<Self>,
        msg: &<Self as Scheme>::Scalar,
    ) -> Result<Vec<u8>, SchemeError> {
        ecies::encrypt::<Self>(public, msg).map_err(SchemeError::Ecies)
    }

    fn decrypt(
        private: &<Self as Scheme>::Scalar,
        encrypted_share: &[u8],
    ) -> Result<<Self as Scheme>::Scalar, SchemeError> {
        ecies::decrypt::<Self>(private, encrypted_share).map_err(SchemeError::Ecies)
    }

    fn tbls_sign(pri_share: &PriShare<Self>, msg: &[u8]) -> Result<SigShare<Self>, SchemeError> {
        tbls::sign(pri_share, msg).map_err(SchemeError::TBls)
    }

    fn tbls_verify(
        public: &PubPoly<Self>,
        msg: &[u8],
        sh: &SigShare<Self>,
    ) -> Result<(), SchemeError> {
        tbls::verify(public, msg, sh).map_err(SchemeError::TBls)
    }

    fn recover_sig(
        public: &PubPoly<Self>,
        msg: &[u8],
        sigs: &[SigShare<Self>],
        t: usize,
    ) -> Result<SigPoint<Self>, SchemeError> {
        tbls::recover(public, msg, sigs, t).map_err(SchemeError::TBls)
    }
}

pub struct Chained;
pub struct Unchained;

use sha2::Digest;
use sha2::Sha256;

pub trait BeaconDigest<S: DrandScheme> {
    fn digest(prev_sig: &[u8], round: u64) -> Vec<u8>;
    fn is_chained() -> bool;
}

impl<S: DrandScheme> BeaconDigest<S> for Chained {
    fn digest(prev_sig: &[u8], round: u64) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(prev_sig);
        h.update(round.to_be_bytes());
        h.finalize().to_vec()
    }

    fn is_chained() -> bool {
        true
    }
}

impl<S: DrandScheme> BeaconDigest<S> for Unchained {
    fn digest(_prev_sig: &[u8], round: u64) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(round.to_be_bytes());
        h.finalize().to_vec()
    }

    fn is_chained() -> bool {
        false
    }
}

use super::error::SchemeError;
use crate::curves::bls12381::G1;
use crate::curves::bls12381::G2;

type Scalar = <G1 as Group>::Scalar;

pub const DEFAULT_SCHEME: &str = "pedersen-bls-chained";

#[derive(Debug, PartialEq)]
pub struct DefaultScheme;

impl DrandScheme for DefaultScheme {
    const ID: &'static str = DEFAULT_SCHEME;
    type Beacon = Chained;
}

impl Scheme for DefaultScheme {
    type Key = G1;
    type Sig = G2;
    type Scalar = Scalar;
}

pub const UNCHAINED_SCHEME: &str = "pedersen-bls-unchained";

#[derive(Debug, PartialEq)]
pub struct UnchainedScheme;

impl DrandScheme for UnchainedScheme {
    const ID: &'static str = UNCHAINED_SCHEME;
    type Beacon = Unchained;
}

impl Scheme for UnchainedScheme {
    type Key = G1;
    type Sig = G2;
    type Scalar = Scalar;
}

pub const SHORT_SIG_SCHEME: &str = "bls-unchained-g1-rfc9380";

#[derive(Debug, PartialEq)]
pub struct SchortSigScheme;

impl Scheme for SchortSigScheme {
    type Key = G2;
    type Sig = G1;
    type Scalar = Scalar;
}

impl DrandScheme for SchortSigScheme {
    const ID: &'static str = SHORT_SIG_SCHEME;
    type Beacon = Unchained;
}
