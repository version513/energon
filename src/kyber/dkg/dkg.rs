use super::protocol::Bundle;
use super::status;
use super::status::StatusMatrix;
use super::status::COMPLAINT;
use super::status::SUCCESS;
use super::structs::*;

use crate::backends::error::BackendsError;
use crate::points::KeyPoint;
use crate::points::KeyPointProjective;
use crate::traits::ScalarField;
use crate::traits::Scheme;

use crate::kyber::ecies;
use crate::kyber::poly;
use crate::kyber::poly::PolyError;
use crate::kyber::poly::PriPoly;
use crate::kyber::poly::PriShare;
use crate::kyber::poly::PubPoly;
use crate::kyber::poly::PubShare;
use crate::kyber::schnorr;
use crate::kyber::schnorr::SchnorrError;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt::Display;
use tracing::*;

#[derive(thiserror::Error, Debug)]
pub enum DkgError {
    #[error("can not run with empty nodes list")]
    NodesEmpty,
    #[error("resharing config needs old nodes list")]
    OldNodesEmpty,
    #[error("resharing config needs old threshold value")]
    OldThresholMissing,
    #[error("public key not found in old list or new list")]
    KeyNotFound,
    #[error("found duplicate in new nodes list: {0}")]
    NewNodesDublicated(u32),
    #[error("found duplicate in old nodes list: {0}")]
    OldNodesDublicated(u32),
    #[error("can't receive new shares without the public polynomial")]
    PubPolyNotFound,
    #[error("new members can't issue deals")]
    NewMembersCanNotIssueDeals,
    #[error("dkg not in the initial state, can't produce deals: {0}")]
    NotInitialPhase(Phase),
    #[error("failed to encrypt si: {0}")]
    EncryptSi(ecies::EciesError),
    #[error("failed to sign a packet: {0}")]
    SignPacket(schnorr::SchnorrError),
    #[error("failed to serialize packet signature: {0}")]
    SignatureSerialize(BackendsError),
    #[error("process_deals can only be called after producing shares - state {0}")]
    OldNodeMemberState(Phase),
    #[error(
        "process_deals can only be called once after creating the dkg for a new member - state {0}"
    )]
    NewNodeMemberState(Phase),
    #[error("node responses list is empty")]
    NoResponsesToSend,
    #[error("can only process responses after processing shares - current state {0}")]
    ResponsePhaseRequired(Phase),
    #[error("dealer key not found, index: {0}")]
    DealerKeyNotFound(u32),
    #[error("invalid bundle signature, index: {0}, err: {1}")]
    BundleSignatureInvalid(u32, SchnorrError),
    #[error("hashing is failed: {0}")]
    HashingIsFailed(BackendsError),
    #[error("private share not found from dealer {0}")]
    ShareNotFound(u32),
    #[error("idx {0} public polynomial is not found from dealer {1}")]
    PubPolyIdxNotFound(u32, u32),
    #[error("final public polynomial or QUAL is empty")]
    FinalValuesAreEmpty,
    #[error("incoming bundles channel closed unexpectedly")]
    BundleChannelClosed,
    #[error("outcoming bundles channel closed unexpectedly")]
    SendOutClosed,
    #[error("phaser channel closed unexpectedly")]
    PhaserChannelClosed,
    #[error("node can only process justifications after processing responses - current state {0}")]
    InvalidStateAtJustification(Phase),
    #[error("our node is evicted from list of qualified participants")]
    Evicted,
    #[error("process-justifications: only {0}/{1} valid deals - dkg abort")]
    NotEnoughValidDeals(u32, u32),
    #[error("not enought qualified nodes: {0}, threshold: {1}")]
    TooManyUncompliant(usize, u32),
    #[error("{0}")]
    RecoverCommit(PolyError),
    #[error("share do not correspond to public polynomial ><")]
    WrongShare,
}

/// Config holds all required information to run a fresh or resharing DKG protocol.
#[derive(Clone)]
pub struct Config<S: Scheme> {
    /// Longterm secret key.
    pub long_term: S::Scalar,
    /// Current group of share holders.
    pub old_nodes: Vec<Node<S>>,
    /// Coefficients of the distributed polynomial needed during the resharing protocol.
    pub public_coeffs: Vec<KeyPoint<S>>,
    /// Expected new group of share holders.
    pub new_nodes: Vec<Node<S>>,
    /// Share to refresh. It will be `None` for new DKG.
    pub share: Option<DistKeyShare<S>>,
    /// The threshold to use in order to reconstruct the secret with the produced
    /// shares. This threshold is with respect to the number of nodes in the
    /// `new_nodes` list. This threshold indicates the degree of the polynomials used to create the shares,
    /// and the minimum number of verification required for each deal.
    pub threshold: u32,
    /// Holds the threshold value that was used in the previous configuration.
    pub old_threshold: u32,
    /// Required to avoid replay attacks from previous runs of a DKG.
    pub nonce: [u8; 32],
    pub log: tracing::Span,
}

impl<S: Scheme> Config<S> {
    pub fn get_dealer_key(&self, index: u32, is_response: bool) -> Result<&KeyPoint<S>, DkgError> {
        let dealers = if is_response || self.old_nodes.is_empty() {
            &self.new_nodes
        } else {
            &self.old_nodes
        };

        dealers
            .iter()
            .find(|node| node.index == index)
            .map(|node| node.public())
            .ok_or(DkgError::DealerKeyNotFound(index))
    }

    pub fn verify_bundle_signature(&self, b: &Bundle<S>) -> Result<(), DkgError> {
        let (msg, key, sig, idx) = match b {
            Bundle::Deal(d) => {
                let index = d.index();
                (
                    d.hash()?,
                    self.get_dealer_key(index, false)?,
                    &d.signature,
                    index,
                )
            }
            Bundle::Response(r) => {
                let index = r.index();
                (
                    r.hash()?,
                    self.get_dealer_key(index, true)?,
                    &r.signature,
                    index,
                )
            }
            Bundle::Justification(j) => {
                let index = j.index();
                (
                    j.hash()?,
                    self.get_dealer_key(index, false)?,
                    &j.signature,
                    index,
                )
            }
        };

        schnorr::verify::<S>(key, &msg, sig)
            .map_err(|err| DkgError::BundleSignatureInvalid(idx, err))
    }
}

// Phase represents all stages of the DKG protocol.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Phase {
    Init,
    Deal,
    Response,
    Justif,
    Finish,
}

impl Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Phase::Init => f.write_str("init"),
            Phase::Deal => f.write_str("deal"),
            Phase::Response => f.write_str("response"),
            Phase::Justif => f.write_str("justification"),
            Phase::Finish => f.write_str("finished"),
        }
    }
}

/// DistKeyGenerator is the main part of DKG protocol.
#[derive(Clone)]
pub(super) struct DistKeyGenerator<S: Scheme> {
    /// Config driving the behavior of DistKeyGenerator
    pub c: Config<S>,
    /// Long term private key
    long: S::Scalar,
    dpriv: PriPoly<S>,
    dpub: PubPoly<S>,
    statuses: StatusMatrix,
    /// The valid shares we received
    valid_shares: BTreeMap<u32, S::Scalar>,
    /// All public polynomials we have seen
    all_publics: BTreeMap<u32, PubPoly<S>>,
    /// List of dealers that clearly gave invalid bundles
    pub evicted: Vec<u32>,
    /// List of share holders that misbehaved during the response phase
    pub evicted_holders: Vec<Index>,
    pub state: Phase,
    /// Index in the old list of nodes
    oidx: Index,
    /// Index in the new list of nodes
    nidx: Index,
    /// Old threshold used in the previous DKG
    old_t: u32,
    /// New threshold to use in this round
    new_t: u32,
    /// Indicates whether we are in the re-sharing protocol or basic DKG
    is_resharing: bool,
    // Indicates whether we are able to issue shares or not
    pub can_issue: bool,
    /// Indicates whether we are able to receive a new share or not
    pub can_receive: bool,
    /// Public polynomial of the old group
    old_pub_poly: PubPoly<S>,
}

/// A helper type that makes logic more explicit at response phase.
pub enum Flow<S: Scheme> {
    /// Finish: DKG is finished successfully and has an output.
    ///
    /// Expected participants:
    /// - Joiner into new group
    /// - Joiner into existing group
    /// - Remainer
    Output(DkgOutput<S>),
    /// Continue: Justifications are required from this node.
    ///
    /// Possible for participants:
    /// - Joiner into new group
    /// - Remainer
    Justif(JustificationBundle<S>),
    /// Continue: Justifications are not required from this node,
    /// but expected from other nodes.
    ///
    /// Possible for participants:
    /// - Joiner into new group
    /// - Joiner into existing group
    /// - Remainer
    WaitingForJustif,
}

impl<S: Scheme> DistKeyGenerator<S> {
    pub fn new(mut c: Config<S>) -> Result<Self, DkgError> {
        if c.new_nodes.is_empty() && c.old_nodes.is_empty() {
            return Err(DkgError::NodesEmpty);
        }

        let is_resharing = c.share.is_some() || !c.public_coeffs.is_empty();
        if is_resharing {
            if c.old_nodes.is_empty() {
                return Err(DkgError::OldNodesEmpty);
            }

            if c.old_threshold == 0 {
                return Err(DkgError::OldThresholMissing);
            }
        }

        let public = S::sk_to_pk(&c.long_term);
        let (mut oidx, old_present) = find_pub(&c.old_nodes, &public);
        let (nidx, new_present) = find_pub(&c.new_nodes, &public);

        if !old_present && !new_present {
            return Err(DkgError::KeyNotFound);
        }

        let new_t = if c.threshold != 0 {
            c.threshold
        } else {
            minimum_t(c.new_nodes.len()) as u32
        };

        // If we are not in the new list of nodes, then we definitely can't receive anything
        let can_receive = new_present;
        // Only joiners into existing group can not issue deals
        let mut can_issue = true;
        let mut secret_coeff = None;

        if !is_resharing && new_present {
            // In fresh dkg case, we consider the old nodes same a new nodes
            c.old_nodes = c.new_nodes.clone();
            (oidx, _) = find_pub(&c.old_nodes, &public);
        } else if let Some(share) = c.share.as_ref() {
            secret_coeff = Some(share.pri_share.value().to_owned())
        } else {
            // Joiner into existing group
            can_issue = false;
        };

        if let Some(idx) = check_for_duplicates(&c.new_nodes) {
            return Err(DkgError::NewNodesDublicated(idx));
        }
        if let Some(idx) = check_for_duplicates(&c.old_nodes) {
            return Err(DkgError::OldNodesDublicated(idx));
        }

        let dpriv = PriPoly::<S>::new(c.threshold, secret_coeff);
        let dpub = dpriv.commit();

        // Old threshold is only useful in the context of a new share holder, to
        // make sure there are enough correct deals from the old nodes.
        let mut old_t = 0;
        // Old public polynomial is empty for fresh DKG
        let mut old_pub_poly: PubPoly<S> = PubPoly { commits: vec![] };

        if is_resharing && new_present {
            match (c.public_coeffs.is_empty(), &c.share) {
                (true, None) => return Err(DkgError::PubPolyNotFound),
                (false, _) => {
                    old_pub_poly.commits = c.public_coeffs.clone();
                }
                (true, Some(ref share)) => {
                    c.public_coeffs = share.commits.clone();
                    old_pub_poly.commits = c.public_coeffs.clone();
                }
            }

            old_t = c.public_coeffs.len() as u32;
        }

        let statuses = StatusMatrix::new(&c.old_nodes, &c.new_nodes, COMPLAINT);
        let long = c.long_term;

        Ok(Self {
            state: Phase::Init,
            long,
            can_receive,
            can_issue,
            is_resharing,
            dpriv,
            dpub,
            oidx,
            nidx,
            c,
            old_t,
            new_t,
            statuses,
            valid_shares: BTreeMap::new(),
            all_publics: BTreeMap::new(),
            old_pub_poly,
            evicted: vec![],
            evicted_holders: vec![],
        })
    }

    pub fn deals(&mut self) -> Result<DealBundle<S>, DkgError> {
        if !self.can_issue {
            return Err(DkgError::NewMembersCanNotIssueDeals);
        }
        if self.state != Phase::Init {
            return Err(DkgError::NotInitialPhase(self.state));
        }

        let mut deals: Vec<Deal> = Vec::with_capacity(self.c.new_nodes.len());
        for node in &self.c.new_nodes {
            // Compute share
            let si = self.dpriv.eval(node.index).into_value();
            if self.can_receive && self.nidx == node.index {
                let _ = self.valid_shares.insert(self.oidx, si);
                let _ = self.all_publics.insert(self.oidx, self.dpub.clone());
                // Set our share as true, because we are not malicious!
                self.statuses.set(self.oidx, self.nidx, SUCCESS);
                // Don't send our share - useless
                continue;
            }
            let cipher = ecies::encrypt::<S>(&node.public, &si).map_err(DkgError::EncryptSi)?;

            debug!(parent: &self.c.log, "creating deal, share_index: {}", node.index);
            deals.push(Deal {
                share_index: node.index,
                encrypted_share: cipher,
            });
        }
        self.state = Phase::Deal;

        let mut bundle = DealBundle {
            dealer_index: self.oidx,
            deals,
            public: self.dpub.commits.clone(),
            session_id: self.c.nonce.to_vec(),
            signature: vec![],
        };
        bundle.signature = self.sign(&bundle)?;

        Ok(bundle)
    }

    /// Process the deals from all the nodes. Each deal for this node is
    /// decrypted and stored. It returns a response bundle if there is any invalid or
    /// missing deals. It returns an error if the node is not in the right state, or
    /// if there is not enough valid shares, i.e. the dkg is failing already.
    pub fn process_deals(
        &mut self,
        bundles: Vec<DealBundle<S>>,
    ) -> Result<ResponseBundle, DkgError> {
        if self.can_issue && self.state != Phase::Deal {
            // Oldnode member is not in the right state
            return Err(DkgError::OldNodeMemberState(self.state));
        }
        if !self.can_issue && self.state != Phase::Init {
            // Newnode member which is not in the old group is not in the right state
            return Err(DkgError::NewNodeMemberState(self.state));
        }

        let mut seen_index = BTreeSet::new();
        for bundle in bundles {
            if self.can_issue && bundle.dealer_index == self.oidx {
                // Dont look at our own deal.
                // Note that's why we are not checking if we are evicted at the end of this function and return an error
                // because we're supposing we are honest and we don't look at our own deal
                continue;
            }

            if !is_index_included(&self.c.old_nodes, bundle.dealer_index) {
                debug!(parent: &self.c.log, "dealer {} is not in old_nodes list", bundle.dealer_index);
                continue;
            }
            if bundle.session_id != self.c.nonce {
                error!(parent: &self.c.log, "evicting deal with invalid session id, dealer: {}",
                bundle.dealer_index);
                self.evicted.push(bundle.dealer_index);
                continue;
            }

            if seen_index.contains(&bundle.dealer_index) {
                // Already saw a bundle from the same dealer - clear sign of
                // cheating so we evict him from the list
                error!(parent: &self.c.log, "deal bundle already seen, evicting the dealer: {}", bundle.dealer_index);
                self.evicted.push(bundle.dealer_index);
                continue;
            }

            let _ = seen_index.insert(bundle.dealer_index);
            let pub_poly = PubPoly::<S> {
                commits: bundle.public,
            };

            for deal in bundle.deals {
                if !is_index_included(&self.c.new_nodes, deal.share_index) {
                    // Invalid index for share holder is a clear sign of cheating
                    // so we evict him from the list and we don't even need to look at the rest
                    error!(parent: &self.c.log, "share holder evicted normally: {}", bundle.dealer_index);
                    self.evicted.push(bundle.dealer_index);
                    break;
                }
                if deal.share_index != self.nidx {
                    // Dont look at other's shares
                    continue;
                }
                match ecies::decrypt::<S>(&self.long, &deal.encrypted_share) {
                    Ok(share) => {
                        // Check if share is valid w.r.t. public commitment
                        let comm = pub_poly.eval(self.nidx).v;
                        let comm_share = S::sk_to_pk(&share);
                        if comm != comm_share {
                            error!(parent: &self.c.log, "deal share invalid wrt public poly, dealer: {}", bundle.dealer_index);
                            // Invalid share - will issue complaint
                            continue;
                        }
                        if self.is_resharing {
                            // Check that the evaluation this public polynomial at 0,
                            // corresponds to the commitment of the previous the dealer's index
                            let old_share_commit = self.old_pub_poly.eval(bundle.dealer_index).v;
                            if let Some(public_commit) = pub_poly.commit() {
                                if &old_share_commit != public_commit {
                                    error!(parent: &self.c.log, "inconsistent share from old member, dealer: {}", bundle.dealer_index);
                                    continue;
                                }
                            } else {
                                error!(parent: &self.c.log, "public_commit can not be empty, dealer: {}", bundle.dealer_index);
                                continue;
                            };
                        }
                        // Share is valid -> store it
                        self.statuses
                            .set(bundle.dealer_index, deal.share_index, true);
                        let _ = self.valid_shares.insert(bundle.dealer_index, share);
                        tracing::info!(parent: &self.c.log, "valid deal processed, received from: {}", bundle.dealer_index)
                    }
                    Err(err) => {
                        error!(parent: &self.c.log, "share decryption invalid, dealer index: {}, error: {err}", bundle.dealer_index);
                        continue;
                    }
                }
            }

            let _ = self.all_publics.insert(bundle.dealer_index, pub_poly);
        }

        // We set to true the status of each node that are present in both list
        // for their respective index -> we assume the share a honest node creates is
        // correct for himself - that he won't create an invalid share for himself
        for dealer in &self.c.old_nodes {
            let (nidx, is_found) = find_pub(&self.c.new_nodes, &dealer.public);
            if !is_found {
                warn!("deals: public key not found for dealer: {}", dealer.index);
                continue;
            }
            self.statuses.set(dealer.index, nidx, true);
        }

        // Producing response part
        let my_shares = self.statuses.statuses_for_share(self.nidx);
        let responses: Vec<Response> = self
            .c
            .old_nodes
            .iter()
            .filter_map(|node| {
                // If the node is evicted, we don't even need to send a complaint or a
                // response since every honest node evicts him as well.
                if self.evicted.iter().any(|evicted| evicted == &node.index) {
                    return None;
                }

                // Note: fast sync is always enabled.
                let status = match my_shares.get(&node.index) {
                    Some(true) => SUCCESS,
                    // dealer[i] did not give a successful share (or absent etc)
                    _ => COMPLAINT,
                };
                if !status {
                    info!(parent: &self.c.log,"complaint towards node {}", node.index)
                }
                Some(Response {
                    dealer_index: node.index,
                    status,
                })
            })
            .collect();

        if responses.is_empty() {
            Err(DkgError::NoResponsesToSend)
        } else {
            let mut bundle = ResponseBundle {
                share_index: self.nidx,
                responses,
                session_id: self.c.nonce.to_vec(),
                signature: vec![],
            };
            bundle.signature = self.sign(&bundle)?;

            self.state = Phase::Response;
            info!(parent: &self.c.log, "sending back {} responses", bundle.responses.len());

            Ok(bundle)
        }
    }

    /// Takes the response from all nodes if any and returns the [`Flow`]
    pub fn process_responses(&mut self, bundles: &[ResponseBundle]) -> Result<Flow<S>, DkgError> {
        if self.state != Phase::Response {
            return Err(DkgError::ResponsePhaseRequired(self.state));
        }

        let flow = self.process_responses_inner(bundles)?;
        self.check_if_evicted(Phase::Response)?;

        Ok(flow)
    }

    fn process_responses_inner(&mut self, bundles: &[ResponseBundle]) -> Result<Flow<S>, DkgError> {
        let mut valid_authors: Vec<Index> = Vec::with_capacity(bundles.len());
        let mut found_complaint = false;

        for bundle in bundles {
            if self.can_issue && bundle.share_index == self.nidx {
                // We dont treat our own response
                continue;
            }
            if !is_index_included(&self.c.new_nodes, bundle.share_index) {
                error!(parent: &self.c.log, "dealer already evicted, index: {}", bundle.share_index);
                continue;
            }
            if bundle.session_id != self.c.nonce {
                error!(parent: &self.c.log, "invalid session id, index: {}", bundle.share_index);
                self.evicted_holders.push(bundle.share_index);
                continue;
            }

            for response in &bundle.responses {
                if !is_index_included(&self.c.old_nodes, response.dealer_index) {
                    // The index of the dealer doesn't exist - clear violation so we evict
                    self.evicted_holders.push(bundle.share_index);
                    error!(parent: &self.c.log, "dealer evicted, index doesn't exist: {}", bundle.share_index );
                    continue;
                }

                self.statuses
                    .set(response.dealer_index, bundle.share_index, response.status);
                if response.status == COMPLAINT {
                    found_complaint = true
                }
                valid_authors.push(bundle.share_index);
            }
        }

        // Make sure all share holders have sent a valid response (success or complaint).
        // We only need to look at the nodes that did not sent any response,
        // since the invalid one are already markes as evicted
        let all_sent = [valid_authors.as_slice(), &self.evicted_holders].concat();
        for n in &self.c.new_nodes {
            if self.nidx == n.index {
                // We dont evict ourself
                continue;
            }
            if !all_sent.iter().any(|i| *i == n.index) {
                error!(parent: &self.c.log, "response not seen from node {} (eviction)", n.index);
                self.evicted_holders.push(n.index)
            }
        }

        // There is no complaint in the responses received and the status matrix
        // is all filled with success that means we can finish the protocol
        if !found_complaint && self.statuses.complete_success() {
            self.state = Phase::Finish;
            let res = self.compute_result()?;
            info!(parent: &self.c.log, "DKG successful");
            return Ok(Flow::Output(res));
        }

        // Check if there are some node who received at least t complaints.
        // In that case, they must be evicted already since their polynomial can
        // now be reconstructed so any observer can sign in its place.
        for n in &self.c.old_nodes {
            let complaints = status::length_complaints(self.statuses.status_of_dealer(&n.index));
            if complaints >= self.c.threshold {
                self.evicted.push(n.index);
                error!(parent: &self.c.log, "response phase eviction of node {}, too many complaints: {complaints}", n.index)
            }
        }

        self.state = Phase::Justif;

        if !self.can_issue {
            debug!(parent: &self.c.log, "flow: new node is waiting for justifications");
            return Ok(Flow::WaitingForJustif);
        }

        // Check if there are justifications this node needs to produce
        let myrow = self.statuses.status_of_dealer(&self.oidx).clone();
        let mut justifications = Vec::with_capacity(self.c.threshold as usize);
        let mut found_justifs = false;
        for (share_index, status) in myrow {
            if status != COMPLAINT {
                continue;
            }
            // Create justifications for the requested share
            let sh = self.dpriv.eval(share_index).into_value();
            justifications.push(Justification {
                share_index,
                share: sh,
            });
            info!(parent: &self.c.log, "producing justifications for node {}", share_index);
            found_justifs = true;
            // Mark those shares as resolved in the statuses
            self.statuses.set(self.oidx, share_index, true)
        }
        if !found_justifs {
            // No justifications required from us!
            debug!(parent: &self.c.log, "flow: waiting for justifications");
            return Ok(Flow::WaitingForJustif);
        }

        let mut bundle = JustificationBundle {
            dealer_index: self.oidx,
            justifications,
            session_id: self.c.nonce.to_vec(),
            signature: vec![],
        };
        bundle.signature = self.sign(&bundle)?;
        info!(parent: &self.c.log, "flow: {} justifications returned", bundle.justifications.len());

        Ok(Flow::Justif(bundle))
    }

    /// Takes the justifications of the nodes and returns the
    /// results if there is enough QUALified nodes, or an error otherwise.
    pub fn process_justifications(
        &mut self,
        bundles: &[JustificationBundle<S>],
    ) -> Result<DkgOutput<S>, DkgError> {
        if self.state != Phase::Justif {
            return Err(DkgError::InvalidStateAtJustification(self.state));
        }

        let mut seen = BTreeSet::new();
        for bundle in bundles {
            if seen.contains(&bundle.dealer_index) {
                // Bundle contains duplicate - clear violation so we evict
                self.evicted.push(bundle.dealer_index);
                error!(parent: &self.c.log, "bundle contains duplicate - evicting dealer {}", bundle.dealer_index);
                continue;
            }

            if self.can_issue && bundle.dealer_index == self.oidx {
                // We dont treat our own justifications
                debug!(parent: &self.c.log, "skipping own justification");
                continue;
            }

            if !is_index_included(&self.c.old_nodes, bundle.dealer_index) {
                // Index is invalid
                error!(parent: &self.c.log, "index is not present in old nodes list - evicting dealer {}", bundle.dealer_index);
                continue;
            }

            if self
                .evicted
                .iter()
                .any(|evicted| evicted == &bundle.dealer_index)
            {
                // Already evicted node
                warn!(parent: &self.c.log, "already evicted dealer {}", bundle.dealer_index);
                continue;
            }

            if bundle.session_id != self.c.nonce {
                self.evicted.push(bundle.dealer_index);
                warn!(parent: &self.c.log, "invalid session id - evicting dealer {}", bundle.dealer_index);
                continue;
            }
            info!(parent: &self.c.log, "basic sanity checks done!");

            let _ = seen.insert(bundle.dealer_index);
            for justif in &bundle.justifications {
                if !is_index_included(&self.c.new_nodes, justif.share_index) {
                    // Invalid index - clear violation so we evict
                    self.evicted.push(bundle.dealer_index);
                    error!(parent: &self.c.log, "invalid index in justifications - evicting dealer {}",bundle.dealer_index);
                    continue;
                }

                if let Some(pub_poly) = self.all_publics.get(&bundle.dealer_index) {
                    // Compare commit and public poly
                    let commit = S::sk_to_pk(&justif.share);
                    let expected = pub_poly.eval(justif.share_index).v;
                    if commit != expected {
                        // invalid justification - evict
                        self.evicted.push(bundle.dealer_index);
                        error!(parent: &self.c.log, "new share commit invalid - evicting dealer {}", bundle.dealer_index);
                        continue;
                    }

                    if self.is_resharing {
                        // Check that the evaluation this public polynomial at 0,
                        // corresponds to the commitment of the previous the dealer's index
                        let old_share_commit = self.old_pub_poly.eval(bundle.dealer_index).v;
                        let public_commit = pub_poly.commit().unwrap(); // TODO: add pubpoly precheck
                        if old_share_commit != *public_commit {
                            // Inconsistent share from old member
                            self.evicted.push(bundle.dealer_index);
                            error!(parent: &self.c.log, "old share commit not equal to public commit - evicting dealer {}", bundle.dealer_index);
                            continue;
                        }
                        info!(parent: &self.c.log, "old share commit and public commit valid for {}",bundle.dealer_index)
                    }
                    // Valid share -> mark OK
                    self.statuses
                        .set(bundle.dealer_index, justif.share_index, SUCCESS);
                    if justif.share_index == self.nidx {
                        // store the share if it's for us
                        info!("justifications: saving our key share");
                        let _ = self.valid_shares.insert(bundle.dealer_index, justif.share);
                    }
                } else {
                    // Dealer hasn't given any public polynomial at the first phase
                    // so we evict directly - no need to look at its justifications
                    self.evicted.push(bundle.dealer_index);
                    error!(parent: &self.c.log, "justifications: public polynomial missing - evicting dealer {}", bundle.dealer_index);
                    break;
                }
            }
        }

        // Check if we are evicted or not
        if let Err(err) = self.check_if_evicted(Phase::Justif) {
            error!(parent: &self.c.log, "justification: {err}");
            return Err(err);
        }

        // Check if there is enough dealer entries marked as all success
        let all_good = self
            .c
            .old_nodes
            .iter()
            .filter(|n| {
                !self.evicted.iter().any(|i| *i == n.index) && self.statuses.all_true(&n.index)
            })
            .count() as u32;

        let target_threshold = {
            // We need enough old QUAL dealers, more than the threshold the old group uses
            if self.is_resharing {
                self.c.old_threshold
            } else {
                self.c.threshold
            }
        };

        if all_good < target_threshold {
            // That should not happen in the threat model but we still returns the
            // fatal error here so DKG do not finish
            return Err(DkgError::NotEnoughValidDeals(all_good, target_threshold));
        }

        // Otherwise it's all good - compute the result
        let out = self.compute_result()?;

        Ok(out)
    }

    /// Returns an error if this node is in one of the two eviction list. This is useful to detect
    /// our own misbehaviour or lack of connectivity: for example if this node can receive messages from others but is
    /// not able to send, everyone will send a complaint about this node, and thus it is going to be evicted.
    /// This method checks if you are and returns an error from the DKG to stop it. Once evicted a node's messages are
    /// not processed anymore and it is left out of the protocol.
    pub fn check_if_evicted(&self, phase: Phase) -> Result<(), DkgError> {
        // * For DKG -> for all phases look at evicted dealers since both lists are the same anyway
        // * For resharing ->  only at response phase we evict some new share holders
        // 	 otherwise, it's only dealers we evict (since deal and justif are made by dealers)
        let (index_to_use, arr) = {
            if self.is_resharing && phase == Phase::Response {
                (self.nidx, &self.evicted_holders)
            } else {
                if !self.can_issue {
                    // We can't be evicted as a new node in this setting
                    return Ok(());
                }
                (self.oidx, &self.evicted)
            }
        };

        for idx in arr {
            if index_to_use == *idx {
                return Err(DkgError::Evicted);
            }
        }

        Ok(())
    }

    pub fn compute_result(&mut self) -> Result<DkgOutput<S>, DkgError> {
        // Add a full complaint row on the nodes that are evicted
        for index in &self.evicted {
            self.statuses.set_all(index, false)
        }
        // Add all the shares and public polynomials together for the deals that are
        // valid ( equivalently or all justified)
        if self.is_resharing {
            // Instead of adding, in this case, we interpolate all shares
            self.compute_resharing_output()
        } else {
            self.compute_dkg_output()
        }
    }

    pub fn compute_dkg_output(&mut self) -> Result<DkgOutput<S>, DkgError> {
        let mut final_share = S::Scalar::zero();
        let mut final_pub = Vec::<KeyPointProjective<S>>::with_capacity(self.new_t as usize);
        let mut nodes = Vec::with_capacity(self.c.old_nodes.len());

        let old_nodes = std::mem::take(&mut self.c.old_nodes);
        for n in old_nodes.into_iter() {
            if !self.statuses.all_true(&n.index) {
                // This dealer has some unjustified shares
                // no need to check the evicted list since the status matrix
                // has been set previously to complaint for those
                continue;
            }

            // However we do need to check for evicted share holders since in this
            // case (DKG) both are the same.
            if self.evicted_holders.iter().any(|i| *i == n.index) {
                continue;
            }

            let sh = self
                .valid_shares
                .get(&n.index)
                .ok_or(DkgError::ShareNotFound(n.index))?;

            let pub_poly = &self
                .all_publics
                .get(&n.index)
                .ok_or(DkgError::PubPolyIdxNotFound(self.nidx, n.index))?
                .commits;

            final_share += sh;

            if final_pub.is_empty() {
                // Map the first poly into projective form
                final_pub = pub_poly.iter().map(|c| c.into()).collect();
            } else {
                for (a, b) in final_pub.iter_mut().zip(pub_poly.iter()) {
                    *a += b;
                }
            }
            nodes.push(n);
        }
        if final_pub.is_empty() || nodes.is_empty() {
            return Err(DkgError::FinalValuesAreEmpty);
        }

        let output = DkgOutput {
            qual: nodes,
            key: DistKeyShare {
                commits: final_pub.into_iter().map(|c| c.into()).collect(),
                pri_share: PriShare::new(self.nidx, final_share),
            },
        };

        Ok(output)
    }

    pub fn compute_resharing_output(&mut self) -> Result<DkgOutput<S>, DkgError> {
        // Only old nodes sends shares
        let mut shares: Vec<PriShare<S>> = Vec::with_capacity(self.c.old_nodes.len());
        let mut coeffs = BTreeMap::new();
        let mut valid_dealers = Vec::with_capacity(self.c.old_nodes.len());

        for n in &self.c.old_nodes {
            if !self.statuses.all_true(&n.index) {
                // This dealer has some unjustified shares
                // no need to check for the evicted list since the status matrix
                // has been set previously to complaint for those
                warn!(parent: &self.c.log, "this dealer has some unjustified shares, index: {}",n.index);
                continue;
            }

            let commitments = &self
                .all_publics
                .get(&n.index)
                .ok_or(DkgError::PubPolyIdxNotFound(self.nidx, n.index))?
                .commits;

            let _ = coeffs.insert(n.index, commitments);
            let sh = self
                .valid_shares
                .get(&n.index)
                .ok_or(DkgError::ShareNotFound(n.index))?;

            shares.push(PriShare::new(n.index, *sh));
            valid_dealers.push(n.index);
        }

        // The private polynomial is generated from the old nodes, thus inheriting
        // the old threshold condition
        let pri_poly = poly::recover_pri_poly(&mut shares, self.old_t as usize).unwrap();
        let pri_share = PriShare::<S>::new(self.nidx, pri_poly.secret().to_owned());

        // Recover public polynomial by interpolating coefficient-wise all polynomials.
        // The new public polynomial must however have "newT" coefficients since it
        // will be held by the new nodes.
        let final_coeffs: Vec<KeyPoint<S>> = (0..self.new_t)
            .map(|i| {
                let mut tmp_coeffs = coeffs
                    .iter()
                    .map(|(j, coeff)| PubShare {
                        i: *j,
                        v: coeff[i as usize].clone(),
                    })
                    .collect::<Vec<PubShare<S>>>();

                // Using the old threshold / length because there are at most
                // len(d.c.OldNodes) i-th coefficients since they are the one generating one
                // each, thus using the old threshold.
                poly::recover_commit(&mut tmp_coeffs, self.old_t).map_err(DkgError::RecoverCommit)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Reconstruct the final public polynomial
        let pub_poly = PubPoly::<S> {
            commits: final_coeffs.clone(),
        };

        if !pub_poly.check(&pri_share) {
            return Err(DkgError::WrongShare);
        }

        // To compute the QUAL in the resharing case, we take each new nodes whose
        // column in the status matrix contains true for all valid dealers.
        // That means:
        // 1. we only look for valid deals
        // 2. we only take new nodes, i.e. new participants, that correctly ran the
        // protocol (i.e. absent nodes will not be counted)
        let mut qual: Vec<Node<S>> = Vec::with_capacity(self.c.new_nodes.len());
        for new_node in &self.c.new_nodes {
            let mut invalid = false;
            // Look if this node is also a dealer which have been misbehaving
            for old_node in &self.c.old_nodes {
                if self.statuses.all_true(&old_node.index) {
                    // It's a valid dealer as well
                    continue;
                }
                if old_node.public() == new_node.public() {
                    // It's an invalid dealer, so we evict him
                    invalid = true;
                    break;
                }
            }
            // We also check if he has been misbehaving during the response phase only
            if !invalid && !self.evicted_holders.iter().any(|i| *i == new_node.index) {
                qual.push(new_node.clone())
            }
        }

        if qual.len() < self.c.threshold as usize {
            return Err(DkgError::TooManyUncompliant(qual.len(), self.c.threshold));
        }

        let out = DkgOutput {
            qual,
            key: DistKeyShare {
                commits: final_coeffs,
                pri_share,
            },
        };

        Ok(out)
    }

    pub fn sign<P: Packet>(&self, p: &P) -> Result<Vec<u8>, DkgError> {
        let msg = p.hash()?;
        let private_key = &self.c.long_term;
        schnorr::sign::<S>(private_key, &msg).map_err(DkgError::SignPacket)
    }
}

/// Checks the lits of node indices in the `old_nodes` and
/// `new_nodes` list. It returns an error if there is a duplicate in either list.
/// Note: It only looks at indices because it is plausible that one party may
/// have multiple indices for the protocol, i.e. a higher "weight".
fn check_for_duplicates<S: Scheme>(nodes: &[Node<S>]) -> Option<u32> {
    let mut seen = BTreeSet::new();
    for node in nodes {
        if !seen.insert(node.index) {
            return Some(node.index);
        };
    }
    None
}

#[inline(always)]
fn is_index_included<S: Scheme>(list: &[Node<S>], index: u32) -> bool {
    list.iter().any(|n| n.index == index)
}

fn find_pub<S: Scheme>(list: &[Node<S>], to_find: &KeyPoint<S>) -> (Index, bool) {
    if let Some(node) = list.iter().find(|node| node.public.eq(to_find)) {
        (node.index, true)
    } else {
        (0, false)
    }
}

pub fn minimum_t(n: usize) -> usize {
    (n >> 1) + 1
}
