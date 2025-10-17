use crate::backends::error::BackendsError;
use crate::backends::error::BlsError;
use crate::kyber::ecies::EciesError;
use crate::kyber::schnorr::SchnorrError;
use crate::kyber::tbls::TBlsError;

/// Top-level error for schemes used in Drand.
#[derive(thiserror::Error, Debug)]
pub enum SchemeError {
    #[error("backends: {0}")]
    Backends(#[from] BackendsError),
    #[error("ecies: {0}")]
    Ecies(#[from] EciesError),
    #[error("schnorr: {0}")]
    Schnorr(#[from] SchnorrError),
    #[error("bls: {0}")]
    Bls(#[from] BlsError),
    #[error("tbls: {0}")]
    TBls(#[from] TBlsError),
    #[error("unknown scheme")]
    UnknownScheme,
}
