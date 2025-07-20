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

/// DistKeyShare holds the share of a distributed key for a participant.
#[derive(PartialEq, Clone, Default)]
pub struct DistKeyShare<S: Scheme> {
    /// Coefficients of the public polynomial holding the public key.
    pub commits: Vec<KeyPoint<S>>,
    /// Share of the distributed secret which is private information.
    pub pri_share: PriShare<S>,
}

impl<S: Scheme> DistKeyShare<S> {
    /// Returns the public key associated with the distributed private key.
    pub fn public(&self) -> &KeyPoint<S> {
        self.commits.first().unwrap()
    }

    /// Returns the coefficients of the public polynomial.
    pub fn commitments(&self) -> &[KeyPoint<S>] {
        &self.commits
    }
}

/// Node represents the public key and its index amongt the list of participants.
/// For a fresh DKG, the index can be anything but we usually take the index that
/// corresponds to the position in the list of participants. For a resharing, if
/// that node is a node that has already ran the DKG, we need to use the same
/// index as it was given in the previous DKG in the list of OldNodes, in the DKG
/// config.
#[derive(Debug, PartialEq, Clone)]
pub struct Node<S: Scheme> {
    pub index: u32,
    pub public: KeyPoint<S>,
}

impl<S: Scheme> Node<S> {
    // If this conversion fails, it's almost certain the nodes are using mismatched schemes
    pub fn deserialize(index: u32, key: &[u8]) -> Option<Self> {
        let public = Affine::deserialize(key).ok()?;

        Some(Self { index, public })
    }

    pub fn public(&self) -> &KeyPoint<S> {
        &self.public
    }
}

// Output of the DKG protocol after it finishes.
// It contains both the list of nodes that successfully ran the protocol and the
// share of the node.
#[derive(PartialEq, Clone)]
pub struct DkgOutput<S: Scheme> {
    pub qual: Vec<Node<S>>,
    pub key: DistKeyShare<S>,
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

/// Packet is a trait for three messages that this used during the different phases.
pub trait Packet: Display {
    type Hasher;

    fn hash(&self) -> Result<HashOutput, DkgError>;
    fn index(&self) -> Index;
}

impl<S: Scheme> Packet for DealBundle<S> {
    type Hasher = Sha256;

    fn hash(&self) -> Result<HashOutput, DkgError> {
        // Sort references into canonical order
        let mut sorted: Vec<_> = self.deals.iter().collect();
        sorted.sort_by_key(|a| a.share_index);

        let mut h = Self::Hasher::new();
        h.update(self.dealer_index.to_be_bytes());
        for public in &self.public {
            let public_bytes = public.serialize().map_err(DkgError::HashingIsFailed)?;
            h.update(public_bytes)
        }

        for deal in sorted {
            h.update(deal.share_index.to_be_bytes());
            h.update(&deal.encrypted_share);
        }
        h.update(&self.session_id);

        Ok(h.finalize().into())
    }

    fn index(&self) -> Index {
        self.dealer_index
    }
}

impl Packet for ResponseBundle {
    type Hasher = Sha256;

    fn hash(&self) -> Result<HashOutput, DkgError> {
        // Sort references into canonical order
        let mut sorted: Vec<_> = self.responses.iter().collect();
        sorted.sort_by_key(|r| r.dealer_index);

        let mut h = Self::Hasher::new();
        h.update(self.share_index.to_be_bytes());

        for resp in sorted {
            h.update(resp.dealer_index.to_be_bytes());
            h.update((resp.status as u8).to_be_bytes())
        }
        h.update(&self.session_id);

        Ok(h.finalize().into())
    }

    fn index(&self) -> Index {
        self.share_index
    }
}

impl<S: Scheme> Packet for JustificationBundle<S> {
    type Hasher = Sha256;

    fn hash(&self) -> Result<HashOutput, DkgError> {
        // Sort references into canonical order
        let mut sorted: Vec<_> = self.justifications.iter().collect();
        sorted.sort_by_key(|j| j.share_index);

        let mut h = Sha256::new();
        h.update(self.dealer_index.to_be_bytes());

        for j in sorted {
            h.update(j.share_index.to_be_bytes());
            let share_bytes = j.share.to_bytes_be().map_err(DkgError::HashingIsFailed)?;
            h.update(share_bytes)
        }

        Ok(h.finalize().into())
    }

    fn index(&self) -> Index {
        self.dealer_index
    }
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
