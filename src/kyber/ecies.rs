use crate::points::KeyPoint;
use crate::traits::Affine;
use crate::traits::Group;
use crate::traits::Projective;
use crate::traits::ScalarField;
use crate::traits::Scheme;

use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use aes_gcm::Key;
use aes_gcm::KeyInit;
use hkdf::Hkdf;
use sha2::Sha256;

// Elliptic Curve Integrated Encryption Scheme (ECIES)
// ref: https://github.com/drand/kyber/blob/master/encrypt/ecies/ecies.go

const KEY_LEN: usize = 32;
const PAYLOAD_LEN: usize = 44; // key + nonce
const CIPHER_LEN: usize = 48;

/// To simplify error nesting structures, the [`EciesError`] has prefixes on variants `Decr` and `Encr`.
#[derive(thiserror::Error, Debug)]
pub enum EciesError {
    #[error("decrypt: invalid message lenght")]
    DecrInvalidMsgLenght,
    #[error("decrypt: hkdf: invalid number of blocks")]
    DecrHkdf,
    #[error("decrypt: failed to reconstruct the ephemeral point R")]
    DecrDeserializeR,
    #[error("decrypt: failed to serialize ikm")]
    DecrSerializeIKM,
    #[error("decrypt: aead error")]
    DecrAead,
    #[error("decrypt: failed to deserialize a field element from plain")]
    DecrScalarDeserialize,
    #[error("ecrypt: failed to serialize ikm")]
    EncDeserializeIKM,
    #[error("ecrypt: hkdf: invalid number of blocks")]
    EncrHkdf,
    #[error("ecrypt: failed to serialize encrypted message")]
    EncrScalarSerialize,
    #[error("ecrypt: aead error")]
    EncrAead,
    #[error("ecrypt: failed to serialize ephemeral point")]
    EncrPointSerialize,
}

pub fn encrypt<S: Scheme>(
    public: &<S::Key as Group>::Affine,
    msg: &S::Scalar,
) -> Result<Vec<u8>, EciesError> {
    // Create ECIES ephemeral elliptic curve scalar and point
    let eph_sk = S::Scalar::random();
    let eph_pk = <S::Key as Group>::Affine::generator() * eph_sk;

    // Produce Diffie–Hellman key and nonce
    let ikm = (eph_sk * public)
        .into()
        .serialize()
        .map_err(|_| EciesError::EncDeserializeIKM)?;
    let mut okm = [0; PAYLOAD_LEN];

    Hkdf::<Sha256>::new(None, ikm.as_ref())
        .expand(&[], &mut okm)
        .map_err(|_| EciesError::EncrHkdf)?;
    let (key, nonce) = okm.split_at(KEY_LEN);

    // Apply AES-GSM
    let aes = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plain = msg
        .to_bytes_be()
        .map_err(|_| EciesError::EncrScalarSerialize)?;
    let mut c = aes
        .encrypt(nonce.into(), plain.as_ref())
        .map_err(|_| EciesError::EncrAead)?;

    let mut deal: Vec<u8> = eph_pk
        .into()
        .serialize()
        .map_err(|_| EciesError::EncrPointSerialize)?
        .into();
    deal.append(&mut c);

    Ok(deal)
}

pub fn decrypt<S: Scheme>(
    private: &S::Scalar,
    encrypted_share: &[u8],
) -> Result<S::Scalar, EciesError> {
    let expected = CIPHER_LEN + <S::Key as Group>::POINT_SIZE;

    if encrypted_share.len() != expected {
        return Err(EciesError::DecrInvalidMsgLenght);
    }

    let (r_bytes, msg_bytes) = encrypted_share.split_at(<S::Key as Group>::POINT_SIZE);
    let r = KeyPoint::<S>::deserialize(r_bytes).map_err(|_| EciesError::DecrDeserializeR)?;

    // Compute shared DH key and derive the symmetric key and nonce via HKDF
    let ikm = (r * private)
        .into()
        .serialize()
        .map_err(|_| EciesError::DecrSerializeIKM)?;
    let mut okm = [0; PAYLOAD_LEN];

    Hkdf::<Sha256>::new(None, ikm.as_ref())
        .expand(&[], okm.as_mut_slice())
        .map_err(|_| EciesError::DecrHkdf)?;
    let (key, nonce) = okm.split_at(KEY_LEN);

    // Decrypt message using AES-GCM
    let aes = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plain = aes
        .decrypt(nonce.into(), msg_bytes)
        .map_err(|_| EciesError::DecrAead)?;
    let share = S::Scalar::from_bytes_be(&plain).map_err(|_| EciesError::DecrScalarDeserialize)?;

    Ok(share)
}
