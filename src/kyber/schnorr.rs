use crate::traits::Affine;
use crate::traits::Group;
use crate::traits::Projective;
use crate::traits::ScalarField;
use crate::traits::Scheme;

// Vanilla Schnorr signature scheme
// ref: https://github.com/drand/kyber/blob/master/sign/schnorr

/// To simplify error nesting structures, the [`SchnorrError`] has prefixes on variants `Sign` and `Verify`.
#[derive(thiserror::Error, Debug)]
pub enum SchnorrError {
    #[error("sign: failed to serialize R public commitment")]
    SignSerializeR,
    #[error("sign: failed to serialize public key")]
    SignSerializePK,
    #[error("sign: failed to serialize a challenge")]
    SignSerializeS,
    #[error("verify: invalid input lenght")]
    VerifyInvalidInputLenght,
    #[error("verify: failed to deserialize R public commitment")]
    VerifyDeserializeR,
    #[error("verify: failed to deserialize a challenge")]
    VerifyDeserializeS,
    #[error("verify: failed to serialize public key")]
    VerifySerializePK,
    #[error("signature is invalid")]
    InvalidSignature,
}

pub fn sign<S: Scheme>(private: &S::Scalar, msg: &[u8]) -> Result<Vec<u8>, SchnorrError> {
    // create random secret k and public point commitment r
    let k = S::Scalar::random();
    let mut r_bytes: Vec<u8> = S::sk_to_pk(&k)
        .serialize()
        .map_err(|_| SchnorrError::SignSerializeR)?
        .into();

    // create hash(public || r || message)
    let public_bytes = S::sk_to_pk(private)
        .serialize()
        .map_err(|_| SchnorrError::SignSerializePK)?;
    let h = S::Scalar::set_bytes(public_bytes.as_ref(), r_bytes.as_ref(), msg);

    // compute response s = k + x*h
    let xh = h * private;
    let s = k + &xh;

    //  return r || s
    let s_bytes = s.to_bytes_be().map_err(|_| SchnorrError::SignSerializeS)?;
    r_bytes.extend_from_slice(s_bytes.as_ref());

    Ok(r_bytes)
}

pub fn verify<S: Scheme>(
    public: &<S::Key as Group>::Affine,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), SchnorrError> {
    let expected = <S::Key as Group>::POINT_SIZE + S::Scalar::SCALAR_SIZE;

    if sig.len() != expected {
        return Err(SchnorrError::VerifyInvalidInputLenght);
    }
    let (r_bytes, s_bytes) = sig.split_at(<S::Key as Group>::POINT_SIZE);
    let r = <S::Key as Group>::Projective::deserialize(r_bytes)
        .map_err(|_| SchnorrError::VerifyDeserializeR)?;
    let s = S::Scalar::from_bytes_be(s_bytes).map_err(|_| SchnorrError::VerifyDeserializeS)?;

    // recompute hash(public || r || msg)
    let public_bytes = public
        .serialize()
        .map_err(|_| SchnorrError::VerifySerializePK)?;
    let h = S::Scalar::set_bytes(public_bytes.as_ref(), r_bytes, msg);

    // compute s = g^s
    let s = <S::Key as Group>::Affine::generator() * s;

    // compute r + a^h
    let mut ah = h * public;
    ah += &r;

    if s != ah {
        return Err(SchnorrError::InvalidSignature);
    }

    Ok(())
}
