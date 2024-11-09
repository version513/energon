use ark_bn254::Fq;
use ark_bn254::G1Affine;
use ark_bn254::G1Projective;

use ark_ff::BigInt;
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

use sha3::digest::FixedOutput;
use sha3::digest::Update;
use sha3::Keccak256;

use std::ops::BitAnd;
use std::ops::BitXor;

/// Implementation straight Shallue and van de Woestijne method of hashing an arbitrary string to a point on bn254 curve.
/// ref: https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#straightline-svdw.
/// NOTE: Keccak-256 hasher used for compatibility with EVM networks.

/// Length of the requested output `expand_message_xmd_keccak256` in bytes
const LEN_IN_BYTES: usize = 96;

/// Input block size of keccak256 in bytes
const S_IN_BYTES: usize = 136;

/// Output size of keccak256 in bytes
const H_OUT: usize = 32;

/// step 3: DST_prime = DST || I2OSP(len(DST), 1)
/// I2OSP ref: https://www.rfc-editor.org/rfc/rfc8017.html#section-4.1
const DST_PRIME: &[u8; 44] = &dst_prime!(crate::curves::bn254::DST_G1);

/// step 5: l_i_b_str = I2OSP(len_in_bytes, 2)
const L_I_B_STR: &[u8] = &[0, 96];

/// I2OSP(0, 1) for step 6
const I2OSP_0_1: &[u8] = &[0];

/// I2OSP(1, 1) for step 8
const I2OSP_1_1: &[u8] = &[1];

/// I2OSP(2, 1) for step 10
const I2OSP_2_1: &[u8] = &[2];

/// I2OSP(3, 1) for step 10
const I2OSP_3_1: &[u8] = &[3];

/// Constants for the SvdW algorithm
struct SvdW {
    b: Fq,
    z: Fq,
    c1: Fq,
    c2: Fq,
    c3: Fq,
    c4: Fq,
}

/// Constanst values from https://github.com/ConsenSys/gnark-crypto/blob/master/ecc/bn254/hash_to_g1.go#L38-L42
const SVDW: SvdW = SvdW {
    // A = 0
    // B = 3,
    b: Fq::new_unchecked(BigInt::new([
        8797723225643362519,
        2263834496217719225,
        3696305541684646532,
        3035258219084094862,
    ])),
    z: Fq::new_unchecked(BigInt::new([
        15230403791020821917,
        754611498739239741,
        7381016538464732716,
        1011752739694698287,
    ])),
    c1: Fq::new_unchecked(BigInt::new([
        1248766071674976557,
        10548065924188627562,
        16242874202584236114,
        560012691975822483,
    ])),
    c2: Fq::new_unchecked(BigInt::new([
        12997850613838968789,
        14304628359724097447,
        2950087706404981016,
        1237622763554136189,
    ])),
    c3: Fq::new_unchecked(BigInt::new([
        8972444824031832946,
        5898165201680709844,
        10690697896010808308,
        824354360198587078,
    ])),
    c4: Fq::new_unchecked(BigInt::new([
        12077013577332951089,
        1872782865047492001,
        13514471836495169457,
        415649166299893576,
    ])),
};

/// Implementation of expand_message_xmd, ref: https://www.rfc-editor.org/rfc/rfc9380.html#name-expand_message_xmd
fn expand_message_xmd_keccak256(msg: &[u8]) -> [u8; LEN_IN_BYTES] {
    // step 1: ell = ceil(len_in_bytes / b_in_bytes)
    // step 2: ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255
    // step 3: DST_prime = DST || I2OSP(len(DST), 1)
    // step 4: Z_pad = I2OSP(0, s_in_bytes)
    // step 5: l_i_b_str = I2OSP(len_in_bytes, 2)
    // step 6: msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
    // step 7: b_0 = H(msg_prime)
    let b_0 = Keccak256::default()
        .chain([0; S_IN_BYTES])
        .chain(msg)
        .chain(L_I_B_STR)
        .chain(I2OSP_0_1)
        .chain(DST_PRIME)
        .finalize_fixed();

    // step 8: b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let b_1 = Keccak256::default()
        .chain(b_0)
        .chain(I2OSP_1_1)
        .chain(DST_PRIME)
        .finalize_fixed();

    // steps 9,10 unrolled:
    //   for i in (2, ..., ell):  b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
    let mut strxor_i2 = [0u8; H_OUT];
    let mut strxor_i3 = [0u8; H_OUT];

    // i = 2
    for i in 0..H_OUT {
        strxor_i2[i] = b_0[i].bitxor(b_1[i]);
    }
    let b_2 = Keccak256::default()
        .chain(strxor_i2)
        .chain(I2OSP_2_1)
        .chain(DST_PRIME)
        .finalize_fixed();

    // i = 3
    for i in 0..H_OUT {
        strxor_i3[i] = b_0[i].bitxor(b_2[i]);
    }
    let b_3 = Keccak256::default()
        .chain(strxor_i3)
        .chain(I2OSP_3_1)
        .chain(DST_PRIME)
        .finalize_fixed();

    // step 11: uniform_bytes = b_1 || ... || b_ell
    let mut out = [0u8; LEN_IN_BYTES];
    out[0..H_OUT].copy_from_slice(&b_1);
    out[H_OUT..H_OUT * 2].copy_from_slice(&b_2);
    out[H_OUT * 2..H_OUT * 3].copy_from_slice(&b_3);

    out
}

impl SvdW {
    /// Straight SW method mapping to curve on G1, returns unchecked point,
    /// ref: https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-shallue-van-de-woestijne-met
    fn map_to_curve_g1_unchecked(&self, u: Fq) -> G1Affine {
        let tv1 = u * u;
        let tv1 = tv1 * self.c1;
        let tv2 = Fq::ONE + tv1;
        let tv1 = Fq::ONE - tv1;
        let tv3 = tv1 * tv2;
        let tv3 = tv3.inverse().expect("should not fail");
        let tv4 = u * tv1;
        let tv4 = tv4 * tv3;
        let tv4 = tv4 * self.c3;
        let x1 = self.c2 - tv4;

        // step 11: gx1 = x1^2
        // step 12: gx1 = gx1 + A
        // step 13: gx1 = gx1 * x1
        //              = x1^3
        let gx1 = x1 * x1 * x1;
        let gx1 = gx1 + self.b;
        let e1 = gx1.legendre().is_qr();
        let x2 = self.c2 + tv4;

        // step 17: gx2 = x2^2
        // step 18: gx2 = gx2 + A
        // step 19: gx2 = gx2 * x2
        //              = x2^3
        let gx2 = x2 * x2 * x2;
        let gx2 = gx2 + self.b;

        // step 21:  e2 = is_square(gx2) AND NOT e1
        let e2 = gx2.legendre().is_qr() & !e1;
        let x3 = tv2 * tv2;
        let x3 = x3 * tv3;
        let x3 = x3 * x3;
        let x3 = x3 * self.c4;
        let x3 = x3 + self.z;

        // step 27: x = CMOV(x3, x1, e1)   # x = x1 if gx1 is square, else x = x3
        let mut x = if e1 { x1 } else { x3 };

        // step 28: x = CMOV(x, x2, e2)    # x = x2 if gx2 is square and gx1 is not
        if e2 {
            x = x2
        };

        // step 29:  gx = x^2
        // step 30:  gx = gx + A
        // step 31:  gx = gx * x
        //              = x^3
        let gx = x * x * x;
        let gx = gx + self.b;

        // step 33: y = sqrt(gx)
        let mut y = gx.sqrt().expect("should not fail");

        // step 34:  e3 = sgn0(u) == sgn0(y)
        // step 35:   y = CMOV(-y, y, e3)
        let mut u_b = Vec::with_capacity(32);
        let mut y_b = Vec::with_capacity(32);

        <Fq as CanonicalSerialize>::serialize_compressed(&u, &mut u_b).expect("should not fail");
        <Fq as CanonicalSerialize>::serialize_compressed(&y, &mut y_b).expect("should not fail");

        // select correct sign of y
        y = if u_b[0].bitand(1) == y_b[0].bitand(1) {
            y
        } else {
            -y
        };

        ark_bn254::G1Affine::new_unchecked(x, y)
    }
}

pub fn map_to_curve_svdw(msg: &[u8]) -> G1Projective {
    let exp_msg = expand_message_xmd_keccak256(msg);

    let u0 = <Fq as PrimeField>::from_be_bytes_mod_order(&exp_msg[..48]);
    let u1 = <Fq as PrimeField>::from_be_bytes_mod_order(&exp_msg[48..]);

    let q0 = G1Affine::from(SVDW.map_to_curve_g1_unchecked(u0));
    let q1 = G1Affine::from(SVDW.map_to_curve_g1_unchecked(u1));

    q0 + q1
}

/// This macro exists only for readability purpose
macro_rules! dst_prime {
    ($arr:expr) => {{
        let mut result = [0; $arr.len() + 1];
        let mut i = 0;

        // DST
        while i < $arr.len() {
            result[i] = $arr[i];
            i += 1;
        }
        // I2OSP(len(DST), 1) = 43
        result[i] = $arr.len() as u8;

        result
    }};
}
use dst_prime;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::bn254_arkworks::test_vectors;
    use ark_serialize::CanonicalDeserialize;
    use num_bigint::BigInt;
    use num_traits::Num;

    #[test]
    fn test_map_to_curve_g1() {
        use ark_ec::AffineRepr;

        let data = test_vectors::map_to_g1_point_t();
        for i in data.iter() {
            let u = fq_from_int(i.U);
            let ref_x = fq_from_int(i.RefX);
            let ref_y = fq_from_int(i.RefY);

            let point = SVDW.map_to_curve_g1_unchecked(u);
            let x: Fq = (*point.x().unwrap()).into();
            let y: Fq = (*point.y().unwrap()).into();

            assert!(point.is_on_curve());
            assert!(point.is_in_correct_subgroup_assuming_on_curve());
            assert!(x == ref_x);
            assert!(y == ref_y);
        }
    }

    fn fq_from_int(str_int: &str) -> Fq {
        let (_, bytes_le) = BigInt::from_str_radix(str_int, 10).unwrap().to_bytes_le();

        if bytes_le.len() < 32 {
            let mut buf = [0u8; 32];
            buf[..bytes_le.len()].copy_from_slice(&bytes_le);

            <Fq as CanonicalDeserialize>::deserialize_compressed(buf.as_slice()).unwrap()
        } else {
            <Fq as CanonicalDeserialize>::deserialize_compressed(bytes_le.as_slice()).unwrap()
        }
    }
}
