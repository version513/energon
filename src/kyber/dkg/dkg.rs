use super::protocol::Bundle;
use super::status::StatusMatrix;
use super::status::COMPLAINT;
use super::status::SUCCESS;
use super::structs::*;

use crate::kyber::ecies;
use crate::kyber::poly::PriPoly;
use crate::kyber::poly::PriShare;
use crate::kyber::poly::PubPoly;
use crate::kyber::schnorr;

use crate::points::KeyPoint;
use crate::points::KeyPointProjective;

use crate::traits::ScalarField;
use crate::traits::Scheme;

use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Display;
use tracing::{error, info};

/// Config holds all required information to run a fresh or resharing DKG protocol.
pub struct Config<S: Scheme> {
    /// Longterm secret key.
    pub long_term: S::Scalar,

    /// Current group of share holders.
    pub old_nodes: Vec<Node<S>>,

    /// Coefficients of the distributed polynomial needed during the resharing protocol.
    pub public_coeffs: Vec<KeyPoint<S>>,

    /// Expected new group of share holders.
    pub new_nodes: Vec<Node<S>>,

    /// Share to refresh. It will be `None` for a new DKG.
    pub share: Option<DistKeyShare<S>>,

    /// The threshold to use in order to reconstruct the secret with the produced
    /// shares. This threshold is with respect to the number of nodes in the
    /// `new_nodes` list. This threshold indicates the degree of the polynomials used to create the shares,
    /// and the minimum number of verification required for each deal.
    pub threshold: u32,

    /// Holds the threshold value that was used in the previous configuration.
    pub old_threshold: u32,

    /// Required to avoid replay attacks from previous runs of a DKG / resharing.
    pub nonce: [u8; 32],
    pub log: tracing::Span,
}

impl<S: Scheme> Config<S> {
    pub fn get_dealer_key(&self, index: u32) -> Result<&KeyPoint<S>, DkgError> {
        // Old nodes are checked to cover reshape case
        let dealers = if self.old_nodes.is_empty() {
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
        let (msg, key, signature) = match b {
            Bundle::Deal(d) => (d.hash()?, self.get_dealer_key(d.index())?, &d.signature),
            Bundle::Response(r) => (r.hash()?, self.get_dealer_key(r.index())?, &r.signature),
            Bundle::Justification(j) => (j.hash()?, self.get_dealer_key(j.index())?, &j.signature),
        };

        schnorr::verify::<S>(key, &msg, signature).map_err(|_| DkgError::BundleSignatureInvalid)
    }
}

// Phase is a type that represents the different stages of the DKG protocol.
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

/// DistKeyGenerator is the struct that runs the DKG protocol.
pub struct DistKeyGenerator<S: Scheme> {
    /// Config driving the behavior of DistKeyGenerator
    pub c: Config<S>,

    /// Long term private key
    long: S::Scalar,

    /// Long term public key
    public: KeyPoint<S>,
    dpriv: PriPoly<S>,
    dpub: PubPoly<S>,
    statuses: StatusMatrix,

    /// The valid shares we received
    valid_shares: HashMap<u32, S::Scalar>,

    /// All public polynomials we have seen
    all_publics: HashMap<u32, PubPoly<S>>,

    /// List of dealers that clearly gave invalid deals / responses / justifs
    evicted: Vec<u32>,

    // List of share holders that misbehaved during the response phase
    evicted_holders: Vec<Index>,
    pub state: Phase,

    /// Index in the old list of nodes
    oidx: Index,

    // Index in the new list of nodes
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
    can_receive: bool,

    /// Indicates whether the node holding the pub key is present in the new list
    new_present: bool,

    /// Indicates whether the node is present in the old list
    old_present: bool,

    /// Already processed our own deal
    processed: bool,

    /// Public polynomial of the old group
    olddpub: PubPoly<S>,
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
                return Err(DkgError::OldThresholdEmpty);
            }
        }

        // can_receive is true by default since in the default DKG mode everyone participates
        let mut can_receive = true;

        let public = S::sk_to_pk(&c.long_term);
        let (mut oidx, mut old_present) = find_pub(&c.old_nodes, &public);
        let (nidx, new_present) = find_pub(&c.new_nodes, &public);

        if !old_present && !new_present {
            return Err(DkgError::KeyNotFound);
        }

        let new_t = if c.threshold != 0 {
            c.threshold
        } else {
            minimum_t(c.new_nodes.len()) as u32
        };

        if !new_present {
            // if we are not in the new list of nodes, then we definitely can't
            // receive anything
            can_receive = false
        }

        let (can_issue, secret_coeff) = if !is_resharing && new_present {
            // in fresh dkg case, we consider the old nodes same a new nodes
            c.old_nodes = c.new_nodes.clone();
            (oidx, old_present) = find_pub(&c.old_nodes, &public);
            (true, S::Scalar::random())
        } else
        // resharing case
        if let Some(share) = &c.share {
            (true, share.private().to_owned())
        } else {
            return Err(DkgError::ProtocolUnknown);
        };

        if let Some(idx) = check_for_duplicates(&c.new_nodes) {
            return Err(DkgError::NewNodesDublicated(idx));
        }
        if let Some(idx) = check_for_duplicates(&c.old_nodes) {
            return Err(DkgError::OldNodesDublicated(idx));
        }

        let dpriv = PriPoly::<S>::new(c.threshold, Some(secret_coeff));
        let dpub = dpriv.commit();

        // resharing case and we are included in the new list of nodes
        let mut old_t = 0;
        let mut olddpub: PubPoly<S> = PubPoly { commits: vec![] };

        // TODO: Refine this after tests are ready.
        if is_resharing && new_present {
            if c.public_coeffs.is_empty() && c.share.is_none() {
                return Err(DkgError::PubPolyNotFound);
            } else if !c.public_coeffs.is_empty() {
                olddpub.commits = c.public_coeffs.to_owned();
            } else if let Some(ref share) = c.share {
                c.public_coeffs = share.public_coeffs().to_vec();
                olddpub.commits = c.public_coeffs.to_owned();
            } else {
                return Err(DkgError::ProtocolReshareUnknown);
            }
            // old threshold is only useful in the context of a new share holder, to
            // make sure there are enough correct deals from the old nodes.
            can_receive = true;
            old_t = c.public_coeffs.len() as u32;
        }
        // Note: fast sync mode is always true
        let statuses = StatusMatrix::new(&c.old_nodes, &c.new_nodes, COMPLAINT);
        let long = c.long_term.to_owned();

        Ok(Self {
            state: Phase::Init,
            long,
            public,
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
            new_present,
            old_present,
            statuses,
            valid_shares: HashMap::new(),
            all_publics: HashMap::new(),
            olddpub,
            evicted: vec![],
            evicted_holders: vec![],
            processed: false,
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
        for node in self.c.new_nodes.iter() {
            // compute share
            let si = self.dpriv.eval(node.index).into_value();
            if self.can_receive && self.nidx == node.index {
                let _ = self.valid_shares.insert(self.oidx, si);
                let _ = self.all_publics.insert(self.oidx, self.dpub.clone());
                // we set our own share as true, because we are not malicious!
                self.statuses.set(self.oidx, self.nidx, SUCCESS);
                // we don't send our own share - useless
                continue;
            }
            let cipher = ecies::encrypt::<S>(&node.public, &si).map_err(DkgError::EncryptSi)?;

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
    ) -> Result<Option<ResponseBundle>, DkgError> {
        if self.can_issue && self.state != Phase::Deal {
            // oldnode member is not in the right state
            return Err(DkgError::OldNodeMemberState(self.state));
        }
        if self.can_receive && !self.can_issue && self.state != Phase::Init {
            // newnode member which is not in the old group is not in the riht state
            return Err(DkgError::NewNodeMemberState(self.state));
        }
        if !self.can_receive {
            // a node that is only in the old group should not process deals
            self.state = Phase::Response; // he moves on to the next phase silently
            return Ok(None);
        }

        let mut seen_index = HashSet::<u32>::new();
        for bundle in bundles {
            if self.can_issue && bundle.dealer_index == self.oidx {
                // dont look at our own deal
                // Note that's why we are not checking if we are evicted at the end of this function and return an error
                // because we're supposing we are honest and we don't look at our own deal
                continue;
            }

            if !is_index_included(&self.c.old_nodes, bundle.dealer_index) {
                error!(parent: &self.c.log, "dealer {} not in old_nodes", bundle.dealer_index);
                continue;
            }
            if bundle.session_id != self.c.nonce {
                error!(parent: &self.c.log, "evicting deal with invalid session id, dealer: {}/n
                bundle nonce: {:?}, protocol nonce: {:?}",
                bundle.dealer_index, bundle.session_id, self.c.nonce

                );
                self.evicted.push(bundle.dealer_index);
                continue;
            }

            if seen_index.contains(&bundle.dealer_index) {
                // already saw a bundle from the same dealer - clear sign of
                // cheating so we evict him from the list
                error!(parent: &self.c.log, "deal bundle already seen, dealer: {}", bundle.dealer_index);
                self.evicted.push(bundle.dealer_index);
                continue;
            }

            let _ = seen_index.insert(bundle.dealer_index);
            let pub_poly = PubPoly::<S> {
                commits: bundle.public,
            };

            // Note: to avoid cloning `pub_poly`, key-value of (bundle.dealer_index, pub_poly) added to `all_publics` after the deals forloop below.
            for deal in bundle.deals {
                if !is_index_included(&self.c.new_nodes, deal.share_index) {
                    // invalid index for share holder is a clear sign of cheating
                    // so we evict him from the list
                    // and we don't even need to look at the rest
                    error!(parent: &self.c.log, "deal share holder evicted normally, dealer: {}", bundle.dealer_index);
                    self.evicted.push(bundle.dealer_index);
                    break;
                }
                if deal.share_index != self.nidx {
                    // we dont look at other's shares
                    continue;
                }
                match ecies::decrypt::<S>(&self.long, &deal.encrypted_share) {
                    Ok(share) => {
                        // check if share is valid w.r.t. public commitment
                        let comm = pub_poly.eval(self.nidx).v;
                        let comm_share = S::sk_to_pk(&share);
                        if comm != comm_share {
                            error!(parent: &self.c.log, "Deal share invalid wrt public poly, dealer: {}", bundle.dealer_index);
                            // invalid share - will issue complaint
                            continue;
                        }
                        if self.is_resharing {
                            // check that the evaluation this public polynomial at 0,
                            // corresponds to the commitment of the previous the dealer's index
                            let old_share_commit = self.olddpub.eval(bundle.dealer_index).v;
                            if let Some(public_commit) = pub_poly.commit() {
                                if &old_share_commit != public_commit {
                                    // inconsistent share from old member
                                    continue;
                                }
                            } else {
                                error!(parent: &self.c.log, "public_commit can not be empty, dealer: {}", bundle.dealer_index);
                                continue;
                            };
                        }
                        // share is valid -> store it
                        self.statuses
                            .set(bundle.dealer_index, deal.share_index, true);
                        let _ = self.valid_shares.insert(bundle.dealer_index, share);
                        tracing::info!(parent: &self.c.log, "valid deal processed, received from dealer: {}", bundle.dealer_index)
                    }
                    Err(err) => {
                        error!(parent: &self.c.log, "deal share decryption invalid, dealer index: {}, error: {err}, encrypted share: {}",bundle.dealer_index, hex::encode(deal.encrypted_share));
                        continue;
                    }
                }
            }

            let _ = self.all_publics.insert(bundle.dealer_index, pub_poly);
        }

        // we set to true the status of each node that are present in both list
        // for their respective index -> we assume the share a honest node creates is
        // correct for himself - that he won't create an invalid share for himself
        for dealer in self.c.old_nodes.iter() {
            let (nidx, is_found) = find_pub(&self.c.new_nodes, &dealer.public);
            if !is_found {
                continue;
            }
            self.statuses.set(dealer.index, nidx, true);
        }

        // producing response part
        let mut responses: Vec<Response> = Vec::with_capacity(self.c.old_nodes.len());
        let my_shares = self.statuses.statuses_for_share(self.nidx);

        for node in self.c.old_nodes.iter() {
            // if the node is evicted, we don't even need to send a complaint or a
            // response since every honest node evicts him as well.
            if self.evicted.iter().any(|evicted| evicted == &node.index) {
                continue;
            }

            // Note: fast sync is always enabled.
            let status = match my_shares.get(&node.index) {
                Some(true) => SUCCESS,
                // dealer[i] did not give a successful share (or absent etc)
                _ => COMPLAINT,
            };
            if !status {
                info!(parent: &self.c.log,"Complaint towards node {}", node.index)
            }
            responses.push(Response {
                dealer_index: node.index,
                status,
            });
        }

        if responses.is_empty() {
            Err(DkgError::NoResponcesToSend)
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

            Ok(Some(bundle))
        }
    }

    pub fn process_responses(&mut self, bundles: &[ResponseBundle]) -> Result<Flow<S>, DkgError> {
        if !self.can_receive && self.state != Phase::Deal {
            return Err(DkgError::OldNodeLeave);
        } else if self.state != Phase::Response {
            return Err(DkgError::ResponsePhaseRequired(self.state));
        }

        let mut valid_authors: Vec<Index> = vec![];
        let mut found_complaint = false;
        for bundle in bundles.iter() {
            if self.can_issue && bundle.share_index == self.nidx {
                // just in case we dont treat our own response
                continue;
            }
            if !is_index_included(&self.c.new_nodes, bundle.share_index) {
                error!(parent: &self.c.log, "response author already evicted, share index: {}", bundle.share_index);
                continue;
            }
            if bundle.session_id != self.c.nonce {
                error!(parent: &self.c.log, "response invalid session id, share index: {}", bundle.share_index);
                self.evicted_holders.push(bundle.share_index);
                continue;
            }

            for response in bundle.responses.iter() {
                if !is_index_included(&self.c.old_nodes, response.dealer_index) {
                    // the index of the dealer doesn't exist - clear violation so we evict
                    self.evicted_holders.push(bundle.share_index);
                    error!(parent: &self.c.log, "response dealer index already evicted, share index: {}", bundle.share_index );
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

        // Note: fast sync is always true.
        //
        // Make sure all share holders have sent a valid response (success or complaint).
        // We only need to look at the nodes that did not sent any response,
        // since the invalid one are already markes as evicted
        let all_sent = [valid_authors.as_slice(), &self.evicted_holders].concat();
        for n in self.c.new_nodes.iter() {
            if self.can_receive && self.nidx == n.index {
                // we dont evict ourself
                continue;
            }
            if !all_sent.iter().any(|i| *i == n.index) {
                error!(parent: &self.c.log, "response not seen from node {} (eviction)", n.index);
                self.evicted_holders.push(n.index)
            }
        }

        // there is no complaint in the responses received and the status matrix
        // is all filled with success that means we can finish the protocol
        if !found_complaint && self.statuses.complete_success() {
            info!(parent: &self.c.log, "DKG successful");
            self.state = Phase::Finish;
            if self.can_receive {
                let out = self.compute_result()?;
                return Ok(Flow::DkgOutput(out));
            } else {
                // old nodes that are not present in the new group
                return Ok(Flow::Leaving);
            }
        }

        // check if there are some node who received at least t complaints.
        // In that case, they must be evicted already since their polynomial can
        // now be reconstructed so any observer can sign in its place.
        Err(DkgError::TODO)
        // TODO: checkIfEvicted
    }

    pub fn compute_result(&mut self) -> Result<DkgOutput<S>, DkgError> {
        self.state = Phase::Finish;
        // add a full complaint row on the nodes that are evicted
        for index in self.evicted.iter() {
            self.statuses.set_all(index, false)
        }
        // add all the shares and public polynomials together for the deals that are
        // valid ( equivalently or all justified)
        if self.is_resharing {
            error!(parent: &self.c.log, "reshape is not implemented yet");
            return Err(DkgError::TODO);
        } else {
            self.compute_dkg_output()
        }
    }

    pub fn compute_dkg_output(&mut self) -> Result<DkgOutput<S>, DkgError> {
        let mut final_share = S::Scalar::zero();
        let mut final_pub = Vec::<KeyPointProjective<S>>::with_capacity(self.new_t as usize);
        let mut nodes: Vec<Node<S>> = vec![];

        // Note: move old nodes out of generator
        let c_old_nodes = std::mem::take(&mut self.c.old_nodes);

        for n in c_old_nodes.into_iter() {
            if !self.statuses.all_true(&n.index) {
                // this dealer has some unjustified shares
                // no need to check the evicted list since the status matrix
                // has been set previously to complaint for those
                continue;
            }

            // however we do need to check for evicted share holders since in this
            // case (DKG) both are the same.
            if self.evicted_holders.iter().any(|i| *i == n.index) {
                continue;
            }

            let sh = self
                .valid_shares
                .get(&n.index)
                .ok_or(DkgError::BUG_ShareNotFound(n.index))?;

            let pub_poly = &self
                .all_publics
                .get(&n.index)
                .ok_or(DkgError::BUG_PubPolyNotFound(self.nidx, n.index))?
                .commits;

            final_share += sh;

            if final_pub.is_empty() {
                // map the first poly into projective form
                final_pub = pub_poly.iter().map(|c| c.into()).collect();
            } else {
                for (a, b) in final_pub.iter_mut().zip(pub_poly.iter()) {
                    *a += b;
                }
            }
            nodes.push(n);
        }
        if final_pub.is_empty() || nodes.is_empty() {
            return Err(DkgError::BUG_FinalValuesAreEmpty);
        }

        let output = DkgOutput {
            qual: nodes,
            key: DistKeyShare {
                commits: DistPublic::new(final_pub.into_iter().map(|c| c.into()).collect()),
                pri_share: PriShare::new(self.nidx, final_share),
            },
        };

        Ok(output)
    }

    pub fn compute_resharing_output(&mut self) -> Result<DkgOutput<S>, DkgError> {
        Err(DkgError::TODO)
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
    let mut seen = HashSet::new();
    for node in nodes {
        if !seen.insert(node.index) {
            return Some(node.index);
        };
    }
    None
}

fn is_index_included<S: Scheme>(list: &[Node<S>], index: u32) -> bool {
    list.iter().any(|n| n.index == index)
}

fn find_pub<S: Scheme>(list: &[Node<S>], to_find: &KeyPoint<S>) -> (Index, bool) {
    for node in list {
        if node.public.eq(to_find) {
            return (node.index, true);
        }
    }
    (0, false)
}

pub fn minimum_t(n: usize) -> usize {
    (n >> 1) + 1
}

#[allow(non_camel_case_types)]
#[derive(thiserror::Error, Debug)]
pub enum DkgError {
    #[error("can't run with empty node list")]
    NodesEmpty,
    #[error("resharing config needs old nodes list")]
    OldNodesEmpty,
    #[error("resharing case needs old threshold field")]
    OldThresholdEmpty,
    #[error("public key not found in old list or new list")]
    KeyNotFound,
    #[error("unknown protocol")]
    ProtocolUnknown,
    #[error("found duplicate in new nodes list: {0}")]
    NewNodesDublicated(u32),
    #[error("found duplicate in old nodes list: {0}")]
    OldNodesDublicated(u32),
    #[error("can't receive new shares without the public polynomial")]
    PubPolyNotFound,
    #[error("unknown protocol for reshare config")]
    ProtocolReshareUnknown,
    #[error("new members can't issue deals")]
    NewMembersCanNotIssueDeals,
    #[error("dkg not in the initial state, can't produce deals: {0}")]
    NotInitialPhase(Phase),
    #[error("failed to encrypt si: {0}")]
    EncryptSi(ecies::EciesError),
    #[error("failed to hash a bundle: {0}")]
    UnknownBundleHash(crate::backends::error::BackendsError),
    #[error("failed to sign a packet: {0}")]
    SignPacket(schnorr::SchnorrError),
    #[error("failed to serialize packet signature: {0}")]
    SignatureSerialize(crate::backends::error::BackendsError),
    #[error("process_deals can only be called after producing shares - state {0}")]
    OldNodeMemberState(Phase),
    #[error(
        "process_deals can only be called once after creating the dkg for a new member - state {0}"
    )]
    NewNodeMemberState(Phase),
    #[error("node responces list is empty")]
    NoResponcesToSend,
    #[error("leaving node can process responses only after creating shares")]
    OldNodeLeave,
    #[error("can only process responses after processing shares - current state {0}")]
    ResponsePhaseRequired(Phase),
    #[error("dealer key not found, index: {0}")]
    DealerKeyNotFound(u32),
    #[error("invalid bundle signature")]
    BundleSignatureInvalid,

    #[error("BUG: hashing is failed: {0}")]
    BUG_FailedToHash(crate::backends::error::BackendsError),
    #[error("BUG: private share not found from dealer {0}")]
    BUG_ShareNotFound(u32),
    #[error("BUG: idx {_0} public polynomial not found from dealer {_1}")]
    BUG_PubPolyNotFound(u32, u32),
    #[error("BUG: final public polynomial or QUAL is empty")]
    BUG_FinalValuesAreEmpty,
    #[error("BUG: board: failed to push deals")]
    BUG_BoardPushDeals,
    #[error("BUG: board: failed to push responses")]
    BUG_BoardPushResponses,
    #[error("BUG: board: failed to push justifications")]
    BUG_BoardPushJustifications,
    #[error("BUG: board: incoming bundles channel closed unexpectedly")]
    BUG_BundleChannelClosed,
    #[error("BUG: phaser channel closed unexpectedly")]
    BUG_PhaserChannelClosed,
    #[error("outcoming bundles channel closed unexpectedly")]
    BUG_SendOutClosed,

    #[error("TODO: reached unfinished logic")]
    TODO,
}
