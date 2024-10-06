use super::error::EciesError;
use super::Scheme;

use crate::traits::Affine;
use crate::traits::Group;
use crate::traits::Projective;
use crate::traits::ScalarField;

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

pub fn encrypt<S: Scheme>(
    public: &<S::Key as Group>::Affine,
    msg: &S::Scalar,
) -> Result<Vec<u8>, EciesError> {
    // Create ECIES ephemeral elliptic curve scalar and point
    let eph_sk = S::Scalar::random();
    let eph_pk = <S::Key as Group>::Affine::generator() * eph_sk;

    // Produce Diffie–Hellman key and nonce
    let ikm = (eph_sk * public).serialize()?;
    let mut okm = [0; PAYLOAD_LEN];

    Hkdf::<Sha256>::new(None, &ikm)
        .expand(&[], &mut okm)
        .map_err(|_| EciesError::Hkdf)?;
    let (key, nonce) = okm.split_at(KEY_LEN);

    // Apply AES-GSM
    let aes = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plain = msg.to_bytes_be()?;
    let mut c = aes
        .encrypt(nonce.into(), plain.as_ref())
        .map_err(|_| EciesError::AeadEncrypt)?;

    let mut deal = eph_pk.serialize()?;
    deal.append(&mut c);

    Ok(deal)
}

pub fn decrypt<S: Scheme>(
    private: &S::Scalar,
    encrypted_share: &[u8],
) -> Result<S::Scalar, EciesError> {
    let expected = CIPHER_LEN + <S::Key as Group>::POINT_SIZE;

    if encrypted_share.len() != expected {
        return Err(EciesError::InvalidInputLenght {
            expected,
            received: encrypted_share.len(),
        });
    }

    let (r_bytes, msg_bytes) = encrypted_share.split_at(<S::Key as Group>::POINT_SIZE);
    let r = <S::Key as Group>::Affine::deserialize(r_bytes)?;

    // Compute shared DH key and derive the symmetric key and nonce via HKDF
    let ikm = (r * private).serialize()?;
    let mut okm = [0; PAYLOAD_LEN];

    Hkdf::<Sha256>::new(None, &ikm)
        .expand(&[], &mut okm[..])
        .map_err(|_| EciesError::Hkdf)?;
    let (key, nonce) = okm.split_at(KEY_LEN);

    // Decrypt message using AES-GCM
    let aes = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plain = aes
        .decrypt(nonce.into(), msg_bytes)
        .map_err(|_| EciesError::AeadDecrypt)?;
    let share = S::Scalar::from_bytes_be(&plain)?;

    Ok(share)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drand::scheme::DefaultScheme;
    use crate::drand::scheme::SchortSigScheme;
    use crate::drand::scheme::UnchainedScheme;

    #[test]
    fn test_ecies() {
        for _ in 0..5 {
            ecies::<DefaultScheme>();
            ecies::<SchortSigScheme>();
            ecies::<UnchainedScheme>();
        }
    }

    fn ecies<S: Scheme>() {
        let private = S::Scalar::random();
        let public = S::sk_to_pk(&private);
        let msg = S::Scalar::random();

        let encrypted_share = S::encrypt(&public, &msg).unwrap();
        let decrypted_share = S::decrypt(&private, &encrypted_share).unwrap();
        assert_eq!(msg, decrypted_share)
    }
}
