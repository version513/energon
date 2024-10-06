use super::error::SchemeError;
use super::poly::PriShare;
use super::poly::PubPoly;
use super::tbls::SigShare;

use crate::traits::Affine;
use crate::traits::Group;
use crate::traits::PairingCurve;
use crate::traits::ScalarField;

use sha2::Digest;
use sha2::Sha256;
use std::ops::Mul;

pub trait Scheme: 'static + Sized + PartialEq {
    const ID: &'static str;
    type Beacon: BeaconDigest<Self>;

    type Key: Group<Scalar = Self::Scalar>
        + PairingCurve<Scalar = Self::Scalar, Pair = <Self::Sig as Group>::Affine>;

    type Sig: Group<Scalar = Self::Scalar>;

    type Scalar: ScalarField
        + for<'a> Mul<&'a <Self::Key as Group>::Affine, Output = <Self::Key as Group>::Projective>;

    fn id(&self) -> &str {
        Self::ID
    }

    fn sk_to_pk(sk: &Self::Scalar) -> <Self::Key as Group>::Affine {
        (<Self::Key as Group>::Affine::generator() * sk).into()
    }

    fn bls_sign(
        msg: &[u8],
        sk: &Self::Scalar,
    ) -> Result<<Self::Sig as Group>::Affine, SchemeError> {
        <Self::Key as PairingCurve>::bls_sign(msg, sk).map_err(SchemeError::Bls)
    }

    fn bls_verify(
        key: &<Self::Key as Group>::Affine,
        sig: &<Self::Sig as Group>::Affine,
        msg: &[u8],
    ) -> Result<(), SchemeError> {
        <Self::Key as PairingCurve>::bls_verify(key, sig, msg).map_err(SchemeError::Bls)
    }

    fn schnorr_sign(private: &Self::Scalar, msg: &[u8]) -> Result<Vec<u8>, SchemeError> {
        super::schnorr::sign::<Self>(private, msg).map_err(SchemeError::Schnorr)
    }

    fn schnorr_verify(
        public: &<Self::Key as Group>::Affine,
        msg: &[u8],
        sig: &[u8],
    ) -> Result<(), SchemeError> {
        super::schnorr::verify::<Self>(public, msg, sig).map_err(SchemeError::Schnorr)
    }

    fn encrypt(
        public: &<Self::Key as Group>::Affine,
        msg: &Self::Scalar,
    ) -> Result<Vec<u8>, SchemeError> {
        super::ecies::encrypt::<Self>(public, msg).map_err(SchemeError::Ecies)
    }

    fn decrypt(
        private: &Self::Scalar,
        encrypted_share: &[u8],
    ) -> Result<Self::Scalar, SchemeError> {
        super::ecies::decrypt::<Self>(private, encrypted_share).map_err(SchemeError::Ecies)
    }

    fn tbls_sign(pri_share: &PriShare<Self>, msg: &[u8]) -> Result<SigShare<Self>, SchemeError> {
        super::tbls::sign(pri_share, msg).map_err(SchemeError::TBls)
    }

    fn tbls_verify(
        public: &PubPoly<Self>,
        msg: &[u8],
        sh: &SigShare<Self>,
    ) -> Result<(), SchemeError> {
        super::tbls::verify(public, msg, sh).map_err(SchemeError::TBls)
    }

    fn recover_sig(
        public: &PubPoly<Self>,
        msg: &[u8],
        sigs: &[SigShare<Self>],
        t: usize,
    ) -> Result<<Self::Sig as Group>::Affine, SchemeError> {
        super::tbls::recover(public, msg, sigs, t).map_err(SchemeError::TBls)
    }
}

pub struct Chained;
pub struct Unchained;

pub trait BeaconDigest<S: Scheme> {
    fn digest(prev_sig: &[u8], round: u64) -> Vec<u8>;
    fn is_chained() -> bool;
}

impl<S: Scheme> BeaconDigest<S> for Chained {
    fn digest(prev_sig: &[u8], round: u64) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(prev_sig);
        h.update(round.to_be_bytes());
        h.finalize().to_vec()
    }

    fn is_chained() -> bool {
        true
    }
}

impl<S: Scheme> BeaconDigest<S> for Unchained {
    fn digest(_prev_sig: &[u8], round: u64) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(round.to_be_bytes());
        h.finalize().to_vec()
    }

    fn is_chained() -> bool {
        false
    }
}

pub const DEFAULT_SCHEME: &str = "pedersen-bls-chained";
pub const UNCHAINED_SCHEME: &str = "pedersen-bls-unchained";
pub const SHORT_SIG_SCHEME: &str = "bls-unchained-g1-rfc9380";

use crate::curves::bls12381::{G1, G2};
type Scalar = <G1 as Group>::Scalar;

#[derive(Debug, PartialEq)]
pub struct DefaultScheme;

impl Scheme for DefaultScheme {
    const ID: &'static str = DEFAULT_SCHEME;
    type Beacon = Chained;
    type Key = G1;
    type Sig = G2;
    type Scalar = Scalar;
}

#[derive(Debug, PartialEq)]
pub struct UnchainedScheme;

impl Scheme for UnchainedScheme {
    const ID: &'static str = UNCHAINED_SCHEME;
    type Beacon = Unchained;
    type Key = G1;
    type Sig = G2;
    type Scalar = Scalar;
}

#[derive(Debug, PartialEq)]
pub struct SchortSigScheme;

impl Scheme for SchortSigScheme {
    const ID: &'static str = SHORT_SIG_SCHEME;
    type Beacon = Unchained;
    type Key = G2;
    type Sig = G1;
    type Scalar = Scalar;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Affine;

    struct Vector {
        round: u64,
        key: &'static str,
        sig: &'static str,
        prev_sig: &'static str,
        scheme: &'static str,
    }

    #[test]
    fn test_beacons() {
        let v = vec![
             //ref: https://github.com/drand/drand/blob/master/crypto/schemes_test.go#L111-L129
            Vector {
                round:     2634945,
                key:      "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31",
                sig:      "814778ed1e480406beb43b74af71ce2f0373e0ea1bfdfea8f9ed62c876c20fcbc7f0163860e3da42ed2148756015f4551451898ffe06d384b4d002245025571b6b7a752f7158b40ad92b13b6d703ad31922a617f2c7f6d960b84d56cf1d79eef",
                prev_sig: "8bd96294383b4d1e04e736360bd7a487f9f409f1e7bd800b720656a310d577b3bdb1e1631af6c5782a1d8979c502f395036181eff4058960fc40bb7034cdae1991d3eda518ab204a077d2f7e724974cf87b407e549bd815cf0b8e5a3832f675d",
                scheme:   "pedersen-bls-chained",
            },
            Vector {
                round:     3361396,
                key:      "922a2e93828ff83345bae533f5172669a26c02dc76d6bf59c80892e12ab1455c229211886f35bb56af6d5bea981024df",
                sig:      "9904b4ec42e82cb42ad53f171cf0510a5eedff8b5e02e2db5a187489f7875307746998b9a6cf82130d291126d4b83cea1048c9b3f07a067e632c20391dc059d22d6a8e835f3980c8bd0183fb6df00a8fbbe6b8c9f61e888dfa76e12af4d4e355",
                prev_sig: "a2377f4e0403f0fd05f709a3292be1b2b59fe990a673ad7b7561b5bd5982b882a2378d36e39befb6ea3bb7aac113c50a18fb07aa4f9a59f95f1aaa7826dafbfcdbf22347c29996c294286fd11b402ad83edd83fa21fe6735fccb65785edbed47",
                scheme:   "pedersen-bls-chained",
            },
            Vector{
                key:      "8200fc249deb0148eb918d6e213980c5d01acd7fc251900d9260136da3b54836ce125172399ddc69c4e3e11429b62c11",
                scheme:   "pedersen-bls-unchained",
                round:     7601003,
                sig:      "af7eac5897b72401c0f248a26b612c5ef68e0ff830b4d78927988c89b5db3e997bfcdb7c24cb19f549830cd02cb854a1143fd53a1d4e0713ded471260869439060d170a77187eb6371742840e43eccfa225657c4cc2d9619f7c3d680470c9743",
                prev_sig: ""
            },
            // ref: https://github.com/randa-mu/drand-client-rs/blob/master/src/verify.rs#L510-L515
            Vector{
                key:      "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
                scheme:   "bls-unchained-g1-rfc9380",
                round:     1000,
                sig:      "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39",
                prev_sig: ""
            },
            // more data available at https://docs.drand.love/docs/dev-guide/3-4-dev-guide-http-api 
        ];

        v.iter().for_each(|i| test_beacon(i));
    }

    fn test_beacon(t: &Vector) {
        fn verify_beacon<S: Scheme>(t: &Vector) {
            let prev_sig = hex::decode(t.prev_sig).unwrap();
            let key = Affine::deserialize(&hex::decode(t.key).unwrap()).unwrap();
            let sig = Affine::deserialize(&hex::decode(t.sig).unwrap()).unwrap();
            let msg = S::Beacon::digest(&prev_sig, t.round);
            S::bls_verify(&key, &sig, &msg).unwrap();
        }

        match t.scheme {
            DefaultScheme::ID => verify_beacon::<DefaultScheme>(t),
            UnchainedScheme::ID => verify_beacon::<UnchainedScheme>(t),
            SchortSigScheme::ID => verify_beacon::<SchortSigScheme>(t),
            _ => panic!(),
        }
    }

    // TODO: add error asserts
}
