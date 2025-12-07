//! Port of the DKG protocol(fast sync mode) from Golang implementation.
//! Source: <https://github.com/drand/kyber/tree/master/share/dkg>

pub(crate) mod dkg;
pub(crate) mod protocol;
pub(crate) mod status;
pub(crate) mod structs;
#[cfg(test)]
mod test;

pub use dkg::{minimum_t, Config, DkgError};
pub use protocol::{Bundle, BundleReceiver, BundleSender, Protocol};
pub use structs::{
    Deal, DealBundle, DistKeyShare, DkgOutput, Justification, JustificationBundle, Node, Response,
    ResponseBundle,
};
