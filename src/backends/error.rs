#[derive(thiserror::Error, Debug, PartialEq)]
pub enum BackendsError {
    // Point
    #[error("point: invalid input lenght")]
    PointInputLen,
    #[error("point: failed to serialize")]
    PointSerialize,
    #[error("point: failed to deserialize")]
    PointDeserialize,
    // Scalar
    #[error("scalar: invalid input lenght")]
    ScalarInputLen,
    #[error("scalar: failed to serialize")]
    ScalarSerialize,
    #[error("scalar: failed to deserialize")]
    ScalarDeserialize,
    #[error("scalar: non-invertable")]
    ScalarNonInvertable,
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
