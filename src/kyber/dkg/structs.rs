use crate::traits::Affine;
use crate::traits::ScalarField;
use crate::traits::Scheme;

use super::dkg::DkgError;
use crate::kyber::poly::PriShare;
use crate::points::KeyPoint;

use sha2::digest::Digest;
use sha2::Sha256;
use std::fmt::Display;

/// Index is an alias to designate the index of a node. The index is used to
/// evaluate the share of a node, and is thereafter fixed. A node will use the
/// same index for generating a partial signature afterwards for example.
pub type Index = u32;

type HashOutput = [u8; 32];

/// Packet is a trait for three messages that this used during the different phases.
/// This allows to verify a DKG packet without knowing its specific type.
pub trait Packet: Display {
    type Hasher;

    fn hash(&self) -> Result<HashOutput, DkgError>;
    fn index(&self) -> Index;
    fn sig(&self) -> &[u8];
}

/// DistKeyShare holds the share of a distributed key for a participant.
#[derive(PartialEq)]
pub struct DistKeyShare<S: Scheme> {
    /// Coefficients of the public polynomial holding the public key.
    pub commits: DistPublic<S>,
    /// Share of the distributed secret which is private information.
    pub pri_share: PriShare<S>,
}

impl<S: Scheme> DistKeyShare<S> {
    pub fn private(&self) -> &S::Scalar {
        self.pri_share.value()
    }

    pub fn public_coeffs(&self) -> &[KeyPoint<S>] {
        self.commits.commits()
    }
}

impl<S: Scheme> DistPublic<S> {
    pub fn new(commits: Vec<KeyPoint<S>>) -> Self {
        Self { commits }
    }

    pub fn commits(&self) -> &[KeyPoint<S>] {
        &self.commits
    }

    pub fn from_bytes(bytes: &[Vec<u8>]) -> Result<Self, crate::backends::error::BackendsError> {
        let mut commits = Vec::with_capacity(bytes.len());

        for commit in bytes.iter() {
            commits.push(Affine::deserialize(commit)?);
        }

        Ok(Self::new(commits))
    }
}

// DistPublic represents the distributed public key generated during a DKG. This
// is the information that can be safely exported to end users verifying a
// drand signature. It is the list of all commitments of the coefficients of the
// private distributed polynomial.
#[derive(Debug, Default, PartialEq)]
pub struct DistPublic<S: Scheme> {
    commits: Vec<KeyPoint<S>>,
}

#[derive(Debug)]
pub struct Node<S: Scheme> {
    pub index: u32,
    pub public: KeyPoint<S>,
}

impl<S: Scheme> Clone for Node<S> {
    fn clone(&self) -> Self {
        Self {
            index: self.index,
            public: self.public.clone(),
        }
    }
}

impl<S: Scheme> Node<S> {
    // if this conversion fails, it's almost certain the nodes are using mismatched schemes
    pub fn deserialize(index: u32, key: &[u8]) -> Option<Self> {
        let public = Affine::deserialize(key).ok()?;

        Some(Self { index, public })
    }

    pub fn public(&self) -> &KeyPoint<S> {
        &self.public
    }
}

/// Deal holds the Deal for one participant as well as the index of the issuing Dealer.
#[derive(Clone)]
pub struct Deal {
    // Index of the share holder
    pub share_index: u32,
    // Encrypted share issued to the share holder
    pub encrypted_share: Vec<u8>,
}

/// DealBundle is the struct sent out by dealers that contains all the deals and
/// the public polynomial.
#[derive(Clone)]
pub struct DealBundle<S: Scheme> {
    pub dealer_index: u32,
    pub deals: Vec<Deal>,
    /// Public coefficients of the public polynomial used to create the shares
    pub public: Vec<KeyPoint<S>>,
    /// SessionID of the current run
    pub session_id: Vec<u8>,
    /// Signature over the hash of the whole bundle
    pub signature: Vec<u8>,
}

impl<S: Scheme> Packet for DealBundle<S> {
    type Hasher = Sha256;

    fn hash(&self) -> Result<HashOutput, DkgError> {
        // sort references into canonical order
        let mut sorted: Vec<_> = self.deals.iter().collect();
        sorted.sort_by_key(|a| a.share_index);

        let mut h = Self::Hasher::new();
        h.update(self.dealer_index.to_be_bytes());
        for public in self.public.iter() {
            let public_bytes = public.serialize().map_err(DkgError::BUG_FailedToHash)?;
            h.update(public_bytes)
        }

        sorted.iter().for_each(|d| {
            h.update(d.share_index.to_be_bytes());
            h.update(&d.encrypted_share);
        });
        h.update(&self.session_id);

        Ok(h.finalize().into())
    }

    fn index(&self) -> Index {
        self.dealer_index
    }

    fn sig(&self) -> &[u8] {
        &self.signature
    }
}

/// Response holds the Response from another participant as well as the index of
/// the target Dealer.
#[derive(Clone, Debug)]
pub struct Response {
    /// Index of the Dealer for which this response is for
    pub dealer_index: u32,
    pub status: bool,
}

/// ResponseBundle is the struct sent out by share holder containing the status
/// for the deals received in the first phase.
#[derive(Clone)]
pub struct ResponseBundle {
    /// Index of the share holder for which these reponses are for
    pub share_index: u32,
    pub responses: Vec<Response>,
    /// SessionID of the current run
    pub session_id: Vec<u8>,
    /// Signature over the hash of the whole bundle
    pub signature: Vec<u8>,
}

impl Packet for ResponseBundle {
    type Hasher = Sha256;

    fn hash(&self) -> Result<HashOutput, DkgError> {
        // sort references into canonical order
        let mut sorted: Vec<_> = self.responses.iter().collect();
        sorted.sort_by_key(|r| r.dealer_index);

        let mut h = Self::Hasher::new();
        h.update(self.share_index.to_be_bytes());
        sorted.iter().for_each(|r| {
            h.update(r.dealer_index.to_be_bytes());
            h.update((r.status as u8).to_be_bytes())
        });
        h.update(&self.session_id);

        Ok(h.finalize().into())
    }

    fn index(&self) -> Index {
        self.share_index
    }

    fn sig(&self) -> &[u8] {
        &self.signature
    }
}

/// JustificationBundle is the struct that contains all justifications for each
/// complaint in the precedent phase.
#[derive(Clone)]
pub struct JustificationBundle<S: Scheme> {
    pub dealer_index: u32,
    pub justifications: Vec<Justification<S>>,
    /// SessionID of the current run
    pub session_id: Vec<u8>,
    /// Signature over the hash of the whole bundle
    pub signature: Vec<u8>,
}

#[derive(Clone)]
pub struct Justification<S: Scheme> {
    pub share_index: u32,
    pub share: S::Scalar,
}

impl<S: Scheme> Packet for JustificationBundle<S> {
    type Hasher = Sha256;

    fn hash(&self) -> Result<HashOutput, DkgError> {
        // sort references into canonical order
        let mut sorted: Vec<_> = self.justifications.iter().collect();
        sorted.sort_by_key(|j| j.share_index);

        let mut h = Sha256::new();
        h.update(self.dealer_index.to_be_bytes());

        for j in sorted.iter() {
            h.update(j.share_index.to_be_bytes());
            let share_bytes = j.share.to_bytes_be().map_err(DkgError::BUG_FailedToHash)?;
            h.update(share_bytes)
        }

        Ok(h.finalize().into())
    }

    fn index(&self) -> Index {
        self.dealer_index
    }

    fn sig(&self) -> &[u8] {
        &self.signature
    }
}

pub struct DkgOutput<S: Scheme> {
    pub qual: Vec<Node<S>>,
    pub key: DistKeyShare<S>,
}

/// Control flow helper type.
pub enum Flow<S: Scheme> {
    DkgOutput(DkgOutput<S>),
    Justification(JustificationBundle<S>),
    // Old nodes that are not present in the new group
    Leaving,
}

impl<S: Scheme> Display for DealBundle<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DealBundle")
    }
}

impl Display for ResponseBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResponseBundle")
    }
}

impl<S: Scheme> Display for JustificationBundle<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JustificationBundle")
    }
}
