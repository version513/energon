#[derive(thiserror::Error, Debug, PartialEq)]
pub enum PointError {
    #[error("invalid input lenght: expected {expected}, received {received}")]
    InvalidInputLenght { expected: usize, received: usize },
    #[error("invalid point")]
    InvalidPoint,
    #[error("serialization: {0}")]
    Serialization(String),
    #[error("input is not canonical")]
    NonCanonicalInput,
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ScalarError {
    #[error("invalid input lenght: expected {expected}, received {received}")]
    InvalidInputLenght { expected: usize, received: usize },
    #[error("serialization: {0}")]
    Serialization(String),
    #[error("not invertable")]
    NonInvertible,
    #[error("input is not canonical")]
    NonCanonicalInput,
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum BlsError {
    #[error("empty message")]
    EmptyMessage,
    #[error("verification is failed")]
    FailedVerification,
    #[error("hash to curve: {0}")]
    HashToCurve(String),
    #[error("failed to sign, resulting point is invalid")]
    Failed,
}
