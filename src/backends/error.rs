#[derive(thiserror::Error, Debug, PartialEq)]
pub enum BackendsError {
    // Scalar: General errors
    #[error("scalar: invalid input lenght")]
    ScalarInputLen,
    #[error("scalar: failed to serialize")]
    ScalarSerialize,
    #[error("scalar: failed to deserialize")]
    ScalarDeserialize,
    #[error("scalar: non-invertable")]
    ScalarNonInvertable,

    // Point: General errors
    #[error("point: invalid input lenght")]
    PointInputLen,
    #[error("point: failed to serialize")]
    PointSerialize,
    #[error("point: failed to deserialize")]
    PointDeserialize,

    // Point: Arkworks related errors for BN254
    #[error("BN254.G1: x not found")]
    UnknownPointG1X,
    #[error("BN254.G1: y not found")]
    UnknownPointG1Y,
    #[error("BN254.G1: failed to serialize x")]
    SerializePointG1X,
    #[error("BN254.G1: failed to serialize y")]
    SerializePointG1Y,
    #[error("BN254.G2: x not found")]
    UnknownPointG2X,
    #[error("BN254.G2: y not found")]
    UnknownPointG2Y,
    #[error("BN254.G2: failed to serialize x")]
    SerializePointG2X,
    #[error("BN254.G2: failed to serialize y")]
    SerializePointG2Y,
}

/// To simplify error nesting structures, the [`BlsError`] has prefixes on variants `Sign` and `Verify`.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum BlsError {
    #[error("sign: received empty message")]
    SignEmptyMessage,
    #[error("sign: can not initialize map to curve hasher")]
    SignMapToCurveHasher,
    #[error("sign: map to curve error")]
    SignMapToCurve,
    #[error("verify: received empty message")]
    VerifyEmptyMessage,
    #[error("verify: map to curve error")]
    VerifyMapToCurve,
    #[error("verify: can not initialize map to curve hasher")]
    VerifyMapToCurveHasher,
    #[error("signature is invalid")]
    InvalidSignature,
}
