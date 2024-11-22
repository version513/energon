use crate::traits::Affine;
use crate::traits::Group;
use crate::traits::Projective;
use crate::traits::ScalarField;
use crate::traits::Scheme;

use super::error::SchnorrError;

// Vanilla Schnorr signature scheme
// ref: https://github.com/drand/kyber/blob/master/sign/schnorr

pub fn sign<S: Scheme>(private: &S::Scalar, msg: &[u8]) -> Result<Vec<u8>, SchnorrError> {
    // create random secret k and public point commitment r
    let k = S::Scalar::random();
    let mut r_bytes = S::sk_to_pk(&k).serialize()?;

    // create hash(public || r || message)
    let public_bytes = S::sk_to_pk(private).serialize()?;
    let h = S::Scalar::set_bytes(&public_bytes, &r_bytes, msg);

    // compute response s = k + x*h
    let xh = h * private;
    let s = k + &xh;

    //  return r || s
    let s_bytes = s.to_bytes_be()?;
    r_bytes.extend_from_slice(&s_bytes);

    Ok(r_bytes)
}

pub fn verify<S: Scheme>(
    public: &<S::Key as Group>::Affine,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), SchnorrError> {
    let expected = <S::Key as Group>::POINT_SIZE + S::Scalar::SCALAR_SIZE;

    if sig.len() != expected {
        return Err(SchnorrError::InvalidInputLenght {
            expected,
            received: sig.len(),
        });
    }
    let (r_bytes, s_bytes) = sig.split_at(<S::Key as Group>::POINT_SIZE);
    let r = <S::Key as Group>::Projective::deserialize(r_bytes)?;
    let s = S::Scalar::from_bytes_be(s_bytes)?;

    // recompute hash(public || r || msg)
    let public_bytes = public.serialize()?;
    let h = S::Scalar::set_bytes(&public_bytes, r_bytes, msg);

    // compute s = g^s
    let s = <S::Key as Group>::Affine::generator() * s;

    // compute r + a^h
    let mut ah = h * public;
    ah += &r;

    if s != ah {
        return Err(SchnorrError::FailedVerification);
    }

    Ok(())
}
