pub mod bls12381 {
    pub const DST_G1: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    pub const DST_G2: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    pub const POINT_SIZE_G1: usize = 48;
    pub const POINT_SIZE_G2: usize = 96;
    pub const SCALAR_SIZE: usize = 32;

    pub struct G1;
    pub struct G2;
}

pub mod bn254 {
    pub const DST_G1: &[u8] = b"BLS_SIG_BN254G1_XMD:KECCAK-256_SVDW_RO_NUL_";
    pub const DST_G2: &[u8] = b"BLS_SIG_BN254G2_XMD:KECCAK-256_SVDW_RO_NUL_";

    pub const POINT_SIZE_G1: usize = 64;
    pub const POINT_SIZE_G2: usize = 128;
    pub const SCALAR_SIZE: usize = 32;

    pub struct G1;
    pub struct G2;
}
