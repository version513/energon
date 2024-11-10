pub mod schemes;
pub mod traits;

use crate::cyber::error::EciesError;
use crate::cyber::error::SchnorrError;
use crate::cyber::error::TBlsError;

use crate::backends::BlsError;

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
}