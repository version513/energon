use crate::backends::error::BlsError;
use crate::backends::error::PointError;
use crate::backends::error::ScalarError;

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

#[derive(thiserror::Error, Debug)]
pub enum SchnorrError {
    #[error("invalid input lenght: expected {expected}, received {received}")]
    InvalidInputLenght { expected: usize, received: usize },
    #[error("{0}")]
    Point(#[from] PointError),
    #[error("{0}")]
    Scalar(#[from] ScalarError),
    #[error("verification is failed")]
    FailedVerification,
}

#[derive(thiserror::Error, Debug)]
pub enum EciesError {
    #[error("invalid input lenght: expected {expected}, received {received}")]
    InvalidInputLenght { expected: usize, received: usize },
    #[error("invalid number of blocks, too large output")]
    Hkdf,
    #[error("decrypt error")]
    AeadDecrypt,
    #[error("encrypt error")]
    AeadEncrypt,
    #[error("{0}")]
    Point(#[from] PointError),
    #[error("{0}")]
    Scalar(#[from] ScalarError),
}

#[derive(thiserror::Error, Debug)]
pub enum TBlsError {
    #[error("{0}")]
    BlsError(#[from] BlsError),
    #[error("{0}")]
    Serialization(String),
    #[error("invalid input lenght: expected {expected}, received {received}")]
    InvalidInputLenght { expected: usize, received: usize },
    #[error("{0}")]
    Point(#[from] PointError),
    #[error("{0}")]
    Scalar(#[from] ScalarError),
}
