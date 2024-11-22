// TODO: add error asserts

//! This module includes full list of supported drand schemes,
//! to execute tests the backends need to be specified, valid options are:
//!    cargo test --features  bls12381_blstrs,bn254_arkworks
//! or
//!    cargo test --features  bls12381_arkworks,bn254_arkworks

#[cfg(test)]
mod tests {

    use crate::traits::Affine;
    use crate::traits::PairingCurve;
    use crate::traits::ScalarField;
    use crate::traits::Scheme;

    use crate::kyber::ecies;
    use crate::kyber::poly::PubPoly;
    use crate::kyber::schnorr;
    use crate::kyber::tbls;
    use crate::kyber::tbls::SigShare;

    use crate::drand::traits::BeaconDigest;
    use crate::drand::traits::DrandScheme;

    use crate::drand::schemes::BN254UnchainedOnG1Scheme;
    use crate::drand::schemes::DefaultScheme;
    use crate::drand::schemes::SigsOnG1Scheme;
    use crate::drand::schemes::UnchainedScheme;

    fn ecies_encrypt_decrypt<S: Scheme>() {
        let private = S::Scalar::random();
        let public = S::sk_to_pk(&private);
        let msg = S::Scalar::random();

        let encrypted_share = ecies::encrypt::<S>(&public, &msg).unwrap();
        let decrypted_share = ecies::decrypt::<S>(&private, &encrypted_share).unwrap();
        assert_eq!(msg, decrypted_share)
    }

    #[test]
    fn test_ecies_encrypt_decrypt() {
        for _ in 0..5 {
            ecies_encrypt_decrypt::<DefaultScheme>();
            ecies_encrypt_decrypt::<UnchainedScheme>();
            ecies_encrypt_decrypt::<SigsOnG1Scheme>();
            ecies_encrypt_decrypt::<BN254UnchainedOnG1Scheme>();
        }
    }

    fn schnorr_sign_verify<S: Scheme>() {
        let private = S::Scalar::random();
        let public = S::sk_to_pk(&private);
        let msg = S::Scalar::random().to_bytes_be().unwrap();
        let sig = schnorr::sign::<S>(&private, &msg).unwrap();
        assert!(schnorr::verify::<S>(&public, &msg, &sig).is_ok())
    }

    #[test]
    fn test_schnorr_sign_verify() {
        for _ in 0..5 {
            schnorr_sign_verify::<DefaultScheme>();
            schnorr_sign_verify::<UnchainedScheme>();
            schnorr_sign_verify::<SigsOnG1Scheme>();
            schnorr_sign_verify::<BN254UnchainedOnG1Scheme>();
        }
    }

    struct Beacon {
        round: u64,
        key: &'static str,
        sig: &'static str,
        prev_sig: &'static str,
        scheme: &'static str,
    }

    fn test_beacon(b: &Beacon) {
        fn verify_beacon<S: DrandScheme>(b: &Beacon) {
            let prev_sig = hex::decode(b.prev_sig).unwrap();
            let key = Affine::deserialize(&hex::decode(b.key).unwrap()).unwrap();
            let sig = Affine::deserialize(&hex::decode(b.sig).unwrap()).unwrap();
            let msg = S::Beacon::digest(&prev_sig, b.round);
            S::bls_verify(&key, &sig, &msg).unwrap();
        }

        match b.scheme {
            DefaultScheme::ID => verify_beacon::<DefaultScheme>(b),
            UnchainedScheme::ID => verify_beacon::<UnchainedScheme>(b),
            SigsOnG1Scheme::ID => verify_beacon::<SigsOnG1Scheme>(b),
            BN254UnchainedOnG1Scheme::ID => verify_beacon::<BN254UnchainedOnG1Scheme>(b),
            _ => panic!(),
        }
    }

    #[test]
    fn test_beacons() {
        let v = vec![
             //ref: https://github.com/drand/drand/blob/master/crypto/schemes_test.go#L111-L129
            Beacon {
                round:     2634945,
                key:      "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31",
                sig:      "814778ed1e480406beb43b74af71ce2f0373e0ea1bfdfea8f9ed62c876c20fcbc7f0163860e3da42ed2148756015f4551451898ffe06d384b4d002245025571b6b7a752f7158b40ad92b13b6d703ad31922a617f2c7f6d960b84d56cf1d79eef",
                prev_sig: "8bd96294383b4d1e04e736360bd7a487f9f409f1e7bd800b720656a310d577b3bdb1e1631af6c5782a1d8979c502f395036181eff4058960fc40bb7034cdae1991d3eda518ab204a077d2f7e724974cf87b407e549bd815cf0b8e5a3832f675d",
                scheme:   "pedersen-bls-chained",
            },
            Beacon {
                round:     3361396,
                key:      "922a2e93828ff83345bae533f5172669a26c02dc76d6bf59c80892e12ab1455c229211886f35bb56af6d5bea981024df",
                sig:      "9904b4ec42e82cb42ad53f171cf0510a5eedff8b5e02e2db5a187489f7875307746998b9a6cf82130d291126d4b83cea1048c9b3f07a067e632c20391dc059d22d6a8e835f3980c8bd0183fb6df00a8fbbe6b8c9f61e888dfa76e12af4d4e355",
                prev_sig: "a2377f4e0403f0fd05f709a3292be1b2b59fe990a673ad7b7561b5bd5982b882a2378d36e39befb6ea3bb7aac113c50a18fb07aa4f9a59f95f1aaa7826dafbfcdbf22347c29996c294286fd11b402ad83edd83fa21fe6735fccb65785edbed47",
                scheme:   "pedersen-bls-chained",
            },
            Beacon{
                key:      "8200fc249deb0148eb918d6e213980c5d01acd7fc251900d9260136da3b54836ce125172399ddc69c4e3e11429b62c11",
                scheme:   "pedersen-bls-unchained",
                round:     7601003,
                sig:      "af7eac5897b72401c0f248a26b612c5ef68e0ff830b4d78927988c89b5db3e997bfcdb7c24cb19f549830cd02cb854a1143fd53a1d4e0713ded471260869439060d170a77187eb6371742840e43eccfa225657c4cc2d9619f7c3d680470c9743",
                prev_sig: ""
            },
             Beacon{
                key:      "00e3e43df8fcc6a8e57a419a72cee58dc97ad27b2cd17db52ca6e173fe2962971d9d20260c7006980bb49ce8a152bb81e43862f0b6a2c49c3a19b457c2892b7302eb4c1d3ebefde8b9eefeabcdc2d8dcef925f270a345c298a6c31a2df23bd4f1319c6bb3b5376e85f1e0ee12359ecc28928593163c4df2d0b9c6d3505e2c02f",
                scheme:   "bls-bn254-unchained-on-g1",
                round:     1,
                sig:      "256867706c495afda16143b5cb7013dc582ee698a096220bb2a7a12e9091603427a95923355cf492d540e4d428e949e46e4e293165f4f30b8b12c51fae591e37",
                prev_sig: ""
            },
            Beacon{
                key:      "047033cd6e8a37849271c7a2b624176ded162fa8d8f309610f0d32cb1b4e647124a1d10d86e51d268e5927b12a772997c47bc39396ef44daf73e29d246b9f56c210e4bb108f94165a6d8005fa82f3265bfde96289bc2fcca42c643997693aedf2e75abeb76348f0f7f96a02bbc7c9cc68aba524008b7b20e9c27353589297096",
                scheme:   "bls-bn254-unchained-on-g1",
                round:     16,
                sig:      "0367ff3a4ae82eb060decfe4d79549d07dbbf490e6c0d800ffe1e5a4edca03af231486e2358564a5c34be1a010bb8afc84e8d347fdf27807e2e987bf430cc222",
                prev_sig: ""
            },
            Beacon{
                key:      "2a8fde29149e45235ddf09a79873f9e830294decd247722ccbf0552c15d1c5231550c146413b9326b9c4f425d16962964e458211c1e4c86f70bd354fa3fbf1d417fcf10dd2edbc8e5f95f27bb975ada01d9625033051e272085e3d25244d3dec19bf704f8c41e0b8dc56e36b6b0ae624448e46f511c4da2a95e5e32c3e270ab8",
                scheme:   "bls-bn254-unchained-on-g1",
                round:     5,
                sig:      "27014bdeb181aac8afe771f67d6c168c46e5a184b6a62cd4c2a155650a992eda2df062eb8aaa87e2712d71bf64e66ea8cf0845b4cfbf4151ba595ae7bce72555",
                prev_sig: ""
            },

            // ref: https://github.com/randa-mu/drand-client-rs/blob/master/src/verify.rs#L510-L515
            Beacon{
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

    fn recover_default<S: Scheme>() {
        let public: PubPoly<S> = PubPoly { commits: vec![
            Affine::deserialize(&hex::decode("981b7605af21a41f044450a032e5087667150dba5bcf0dddfa95577fc5cabeb0c868806d459419ac80dd7719eadc957b").unwrap()).unwrap(),
            Affine::deserialize(&hex::decode("b6be23db8a387de50341d552d05431d0bd7eccdd0e9b8c162166127cc5a6b0c6db660e3f4d28122cb013b9ab14c29471").unwrap()).unwrap()
            ],
        };
        let msg = hex::decode("1259db124468be37bc0d6d3fb7d7d8bb069cbfb4c6bad8f7a1cac775fe71c45d")
            .unwrap();
        let s1=SigShare::deserialize(&hex::decode("0001b5159d30961ed801eb748971ff6a6ce70acb61e76b8ced40322ae977085963670322443ae1dc3e54889befdeaef8766412e1c0c9c2ffc06f929af7bd1a20514ae39cb43f74ee993ec01cb1cc896aeca223a4e510b6fa90b72f4d6b9622973a73").unwrap()).unwrap();
        let s0=SigShare::deserialize(&hex::decode("00008c699f8a94765d743a3adfa507c5978b2c5ae3de611e2f21c943ca3e8a506faf2fac51681f3b8900cfb25469ded00ae90387905d6f1ae71a85109056956d71956971bc5041bb059429868c9c3a0fbd504f6204a7661164b79a7920fa2cba0c9b").unwrap()).unwrap();
        let sigs = vec![s0, s1];
        let t = 2;

        let recovered = tbls::recover(&public, &msg, &sigs, t).unwrap();
        let required=Affine::deserialize(&hex::decode("a5ca5628c4c88b33d33f5dce6c0992289e9134eaf3b6e441053ebae4e4a309829982c658fde1f4899a729c8ac37803b90b138ca7e64b5ad53fcf726841b0ef70515f2348d07924af4c430f7a899d2689bb2dab5ef0381e6b2aaea0e4948b215c").unwrap()).unwrap();

        assert_eq!(recovered, required);

        // verify_recovered
        <S::Key as PairingCurve>::bls_verify(&public.commits[0], &recovered, &msg).unwrap();
    }

    #[test]
    fn test_recover_default() {
        recover_default::<DefaultScheme>();
    }
}
