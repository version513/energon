pub mod schemes;
pub mod traits;

use crate::backends::error::PointError;
use crate::kyber::error::EciesError;
use crate::kyber::error::SchnorrError;
use crate::kyber::error::TBlsError;

use crate::backends::error::BlsError;

#[derive(thiserror::Error, Debug)]
pub enum SchemeError {
    #[error("{0}")]
    Ecies(#[from] EciesError),
    #[error("{0}")]
    Schnorr(#[from] SchnorrError),
    #[error("{0}")]
    Bls(#[from] BlsError),
    #[error("{0}")]
    TBls(#[from] TBlsError),
    #[error(transparent)]
    Point(#[from] PointError),
    #[error("unknown scheme")]
    UnknownScheme,
}
