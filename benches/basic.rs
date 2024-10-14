use crate::api_overhead_blstrs::bls_api;
use crate::api_overhead_blstrs::bls_blstrs;
use criterion::black_box;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use energon::schemes::drand::DefaultScheme;

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("bls_blstrs", |b| b.iter(|| black_box(bls_blstrs())));
    c.bench_function("bls_api --feature <feature>", |b| {
        b.iter(|| black_box(bls_api::<DefaultScheme>()))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

mod api_overhead_blstrs {
    use group::ff::Field;
    use group::prime::PrimeCurveAffine;
    use group::Group;
    use pairing::MillerLoopResult;
    use pairing::MultiMillerLoop;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use std::ops::Neg;

    const MSG: [u8; 7] = [1, 2, 3, 4, 5, 6, 7];
    const DST_G2: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    pub fn bls_blstrs() {
        let mut rng = ChaChaRng::from_entropy();
        let private = blstrs::Scalar::random(&mut rng);
        let public: blstrs::G1Affine = (blstrs::G1Affine::generator() * &private).into();

        let sig = {
            let p = blstrs::G2Projective::hash_to_curve(&MSG, DST_G2, &[]);
            let mut sig = blstrs::G2Affine::default();
            unsafe {
                blst_lib::blst_sign_pk2_in_g1(
                    std::ptr::null_mut(),
                    sig.as_mut(),
                    p.as_ref(),
                    &private.into(),
                );
            }
            sig
        };

        let is_valid: bool = {
            let msg: blstrs::G2Affine =
                blstrs::G2Projective::hash_to_curve(&MSG, DST_G2, &[]).into();
            let g = blstrs::G1Affine::generator();
            let p1 = (&public.neg(), &blstrs::G2Prepared::from(msg));
            let p2 = (&g, &blstrs::G2Prepared::from(sig));

            blstrs::Bls12::multi_miller_loop(&[p1, p2])
                .final_exponentiation()
                .is_identity()
                .into()
        };

        assert!(is_valid)
    }

    use energon::schemes::drand::DrandScheme as Scheme;
    use energon::traits::ScalarField;

    pub fn bls_api<S: Scheme>() {
        let private = S::Scalar::random();
        let public = S::sk_to_pk(&private);
        let sig = S::bls_sign(&MSG, &private).unwrap();
        let is_valid = S::bls_verify(&public, &sig, &MSG).is_ok();

        assert!(is_valid)
    }
}
