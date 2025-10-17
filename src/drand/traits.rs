use crate::traits::PairingCurve;
use crate::traits::Scheme;

use crate::kyber::ecies;
use crate::kyber::poly::PriShare;
use crate::kyber::poly::PubPoly;
use crate::kyber::schnorr;
use crate::kyber::tbls;
use crate::kyber::tbls::SigShare;

use crate::points::KeyPoint;
use crate::points::SigPoint;

use super::error::SchemeError;

pub trait DrandScheme: Scheme + 'static + Sized + PartialEq + Clone + Default {
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
        sigs: Vec<SigShare<Self>>,
        t: usize,
    ) -> Result<SigPoint<Self>, SchemeError> {
        tbls::recover(public, msg, sigs, t).map_err(SchemeError::TBls)
    }
}

pub trait BeaconDigest<S: DrandScheme> {
    fn digest(prev_sig: &[u8], round: u64) -> [u8; 32];
    fn is_chained() -> bool;
}
