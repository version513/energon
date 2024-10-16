mod backends;
pub mod curves;
pub mod cyber;
pub mod examples;
pub mod schemes;
pub mod traits;

pub mod points {
    use crate::traits::Group;
    use crate::traits::Scheme;

    /// Keygroup point in affine representation
    pub type KeyPoint<S> = <<S as Scheme>::Key as Group>::Affine;

    /// Siggroup point in affine representation
    pub type SigPoint<S> = <<S as Scheme>::Sig as Group>::Affine;

    /// Keygroup point in projective representation
    pub type KeyPointProjective<S> = <<S as Scheme>::Key as Group>::Projective;

    /// Siggroup point in projective representation
    pub type SigPointProjective<S> = <<S as Scheme>::Sig as Group>::Projective;
}
