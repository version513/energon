#[cfg(all(feature = "bls12381_blstrs", feature = "bls12381_arkworks"))]
compile_error!("Features 'bls12381_blstrs' and 'bls12381_arkworks' are mutually exclusive");

#[cfg(feature = "bls12381_blstrs")]
mod bls12381_blstrs {
    mod g1;
    mod g2;
    mod scalar;

    use crate::curves::bls12381;
    use std::convert::Infallible;

    super::impl_groups!(bls12381);

    /// Infallible serializer for blstrs scalar and points
    /// Used internally to simplify public traits bounds.
    trait Serializer {
        type Output;

        fn serialize(&self) -> Result<Self::Output, Infallible>;
    }

    impl From<Infallible> for super::error::BackendsError {
        #[inline]
        fn from(infallible: Infallible) -> super::error::BackendsError {
            match infallible {}
        }
    }
}

#[cfg(feature = "bls12381_arkworks")]
mod bls12381_arkworks {
    mod g1;
    mod g2;
    mod scalar;

    use crate::curves::bls12381;
    super::impl_groups!(bls12381);
}

#[cfg(feature = "bn254_arkworks")]
mod bn254_arkworks {
    mod g1;
    mod g2;
    mod hash_to_curve_on_g1;
    mod scalar;
    #[cfg(test)]
    mod test_vectors;

    use crate::curves::bn254;
    super::impl_groups!(bn254);
}

macro_rules! impl_groups {
    ($curve:ident) => {
        use crate::traits::Group;

        impl Group for $curve::G1 {
            const DST: &'static [u8] = $curve::DST_G1;
            const POINT_SIZE: usize = $curve::POINT_SIZE_G1;

            type Affine = g1::G1Affine;
            type Projective = g1::G1Projective;
            type Scalar = scalar::Scalar;
        }

        impl Group for $curve::G2 {
            const DST: &'static [u8] = $curve::DST_G2;
            const POINT_SIZE: usize = $curve::POINT_SIZE_G2;

            type Affine = g2::G2Affine;
            type Projective = g2::G2Projective;
            type Scalar = scalar::Scalar;
        }
    };
}

pub(in crate::backends) use impl_groups;
pub mod error;
