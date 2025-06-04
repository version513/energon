use super::dkg::Config;
use super::dkg::DistKeyGenerator;
use super::dkg::DkgError;
use super::dkg::Flow;
use super::dkg::Phase;
use super::structs::*;
use crate::traits::Scheme;

use std::collections::BTreeMap;
use std::fmt::Display;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::*;

/// Sender to forward bundles to the [`Protocol`].
pub type BundleSender<T> = mpsc::Sender<Bundle<T>>;

/// Receiver to receive bundles from the [`Protocol`].
pub type BundleReceiver<T> = mpsc::Receiver<Bundle<T>>;

/// Board serves as a transport between DKG protocol and application layer.
struct Board<S: Scheme> {
    /// Inner receiver with associated [`BundleSender`].
    rx_in: Option<mpsc::Receiver<Bundle<S>>>,
    /// Inner sender with associated [`BundleReceiver`].
    tx_out: mpsc::Sender<Bundle<S>>,
}

impl<S: Scheme> Board<S> {
    fn receiver(&mut self) -> mpsc::Receiver<Bundle<S>> {
        self.rx_in.take().expect("value is never missing")
    }

    async fn push_deals(&self, bundle: DealBundle<S>) -> Result<(), DkgError> {
        self.tx_out
            .send(Bundle::Deal(bundle))
            .await
            .map_err(|_| DkgError::SendOutClosed)
    }

    async fn push_responses(&self, bundle: ResponseBundle) -> Result<(), DkgError> {
        self.tx_out
            .send(Bundle::Response(bundle))
            .await
            .map_err(|_| DkgError::SendOutClosed)
    }

    async fn push_justifications(&self, bundle: JustificationBundle<S>) -> Result<(), DkgError> {
        self.tx_out
            .send(Bundle::Justification(bundle))
            .await
            .map_err(|_| DkgError::SendOutClosed)
    }
}

/// Phaser signals on its channel when the protocol should move to the next [`PhaseTime`] by timeout.
struct Phaser {
    new_phase: mpsc::Receiver<PhaseTime>,
}

/// Sequential phases invoked by `Phaser`.
enum PhaseTime {
    Response,
    Justification,
    Finish,
}

impl Phaser {
    fn init(phase_timeout: Duration) -> Self {
        let (tx, rx) = mpsc::channel::<PhaseTime>(1);
        tokio::task::spawn(async move {
            let mut interval = tokio::time::interval(phase_timeout);
            // First tick completes immediately
            interval.tick().await;
            interval.tick().await;
            let _ = tx.send(PhaseTime::Response).await;
            interval.tick().await;
            let _ = tx.send(PhaseTime::Justification).await;
            interval.tick().await;
            let _ = tx.send(PhaseTime::Finish).await;
        });

        Self { new_phase: rx }
    }
}

/// Protocol is an asynchronous wrapper around [`DistKeyGenerator`].
pub struct Protocol<S: Scheme> {
    dkg: DistKeyGenerator<S>,
    phase_timeout: Duration,
    board: Board<S>,
}

impl<S: Scheme> Protocol<S> {
    /// Initializes new DKG protocol from given configuration.
    ///
    /// Returns a triplet:
    /// - Protocol instance to run (see [`Self::run`]).
    /// - `BundleReceiver` for receving bundles from the protocol (protocol → external).
    /// - `BundleSender` for sending bundles to the protocol (external → protocol).
    pub fn new_dkg(
        c: Config<S>,
        phase_timeout: Duration,
    ) -> Result<(Self, BundleReceiver<S>, BundleSender<S>), DkgError> {
        let dkg = DistKeyGenerator::new(c)?;
        // Channel for bundles input
        let (tx_in, rx_in) = mpsc::channel::<Bundle<S>>(1);
        // Channel for bundles output
        let (tx_out, rx_out) = mpsc::channel::<Bundle<S>>(1);
        let board = Board {
            rx_in: Some(rx_in),
            tx_out,
        };
        let protocol = Self {
            dkg,
            phase_timeout,
            board,
        };

        Ok((protocol, rx_out, tx_in))
    }

    pub async fn run(mut self) -> Result<Option<DkgOutput<S>>, DkgError> {
        let mut deals = Set::<DealBundle<S>>::new();
        let mut resps = Set::<ResponseBundle>::new();
        let mut justifs = Set::<JustificationBundle<S>>::new();
        let new_n = self.dkg.c.new_nodes.len();
        let old_n = self.dkg.c.old_nodes.len();

        let mut bundle_rx = self.board.receiver();
        let mut phaser = Phaser::init(self.phase_timeout);

        self.send_deals().await?;
        // At this point DKG protocol is finished correctly for leaving participants.
        if !self.dkg.can_receive {
            return Ok(None);
        }

        loop {
            tokio::select! {
                next_phase = phaser.new_phase.recv()=>{ if let Some(phase) = next_phase{
                    match phase{
                        PhaseTime::Response=>{
                            warn!(parent: self.log(), "phaser: moving to response phase, got {} deals", &deals.len());
                            self.to_resp(&mut deals).await?;
                        },
                        PhaseTime::Justification=>{
                            if self.phase() == Phase::Response{
                                warn!(parent: self.log(), "phaser: moving to justifications phase, got {} resps", &resps.len());
                                match self.dkg.process_responses(&resps.take())? {
                                    Flow::Output(out) => break Ok(Some(out)),
                                    Flow::Justif(just) => {
                                        self.board.push_justifications(just).await?
                                    }
                                    // Justifications are expected from other nodes
                                    Flow::WaitingForJustif => {},
                                    }
                                }
                            },
                        PhaseTime::Finish=> {
                            // Whatever happens here, if phaser says it's finished we finish
                            let out = self.dkg.process_justifications(&justifs.take())?;
                            break Ok(Some(out));
                        },
                    }} else { return Err(DkgError::PhaserChannelClosed) }
                }
                new_bundle = bundle_rx.recv()=>{ if let Some(bundle) = new_bundle{
                    if let Err(err) = self.dkg.c.verify_bundle_signature(&bundle){
                        error!(parent: self.log(), "ignoring new {bundle}, reason: {err}");
                    } else {
                        match bundle {
                            Bundle::Deal(new_deal) =>{
                                deals.push(new_deal)?;
                                if deals.len() == old_n{
                                    info!(parent: self.log(), "fast moving to response phase, got {old_n} deals, current phase: {}", self.phase());
                                    self.to_resp(&mut deals).await?;

                                }
                            },
                            Bundle::Response(new_resp) =>{
                                resps.push(new_resp)?;
                                if resps.len() == new_n{
                                    info!(parent: self.log(), "fast moving to justifications phase, got {new_n} resps, current phase: {}", self.phase());
                                    if self.phase() == Phase::Response{
                                        match self.dkg.process_responses(&resps.take())? {
                                            Flow::Output(out) => break Ok(Some(out)),
                                            Flow::Justif(just) => {
                                                info!(parent: self.log(), "sendJustifications, sending, from {} responses", resps.len());
                                                self.board.push_justifications(just).await?
                                            }
                                            // Justifications are expected from other nodes.
                                            Flow::WaitingForJustif => {},
                                        }
                                    }
                                }
                            },
                            Bundle::Justification(new_just) => {
                                justifs.push(new_just)?;
                                if justifs.len()==old_n{
                                    // We finish only if it's time to do so, maybe we received
                                    // justifications but are not in the right phase yet since it
                                    // may not be the right time or haven't received enough msg from
                                    // previous phase
                                    if self.phase()==Phase::Justif{
                                        let out= self.dkg.process_justifications(&justifs.take())?;
                                        break Ok(Some(out));
                                    }
                                }
                            },
                        }
                    }
                } else { return Err(DkgError::BundleChannelClosed) }}
            }
        }
    }

    async fn to_resp(&mut self, deals: &mut Set<DealBundle<S>>) -> Result<(), DkgError> {
        // For all dealers, we should be in the DealPhase
        if self.can_issue() && self.phase() == Phase::Deal ||
        // For all *new* share holders, we should be in the InitPhase
        !self.can_issue() && self.phase() == Phase::Init
        {
            self.send_responses(deals.take()).await?
        }

        Ok(())
    }

    async fn send_deals(&mut self) -> Result<(), DkgError> {
        if self.can_issue() {
            let bundle = self.dkg.deals()?;
            info!(parent: self.log(), "send_deals, sending out deal bundle {} deals",bundle.deals.len());
            self.board.push_deals(bundle).await
        } else {
            Ok(())
        }
    }

    async fn send_responses(&mut self, deals: Vec<DealBundle<S>>) -> Result<(), DkgError> {
        let deals_len = deals.len();
        let bundle = self.dkg.process_deals(deals)?;
        info!(parent: self.log(), "send_responses, sending out {} responses, from {deals_len} deals", bundle.responses.len());
        self.board.push_responses(bundle).await?;

        Ok(())
    }

    fn phase(&self) -> Phase {
        self.dkg.state
    }

    fn can_issue(&self) -> bool {
        self.dkg.can_issue
    }

    #[inline(always)]
    fn log(&self) -> &tracing::Span {
        &self.dkg.c.log
    }
}

struct Set<P: Packet> {
    vals: BTreeMap<Index, P>,
    bad: Vec<Index>,
}

impl<P: Packet> Set<P> {
    fn new() -> Self {
        Self {
            vals: BTreeMap::new(),
            bad: vec![],
        }
    }

    fn push(&mut self, p: P) -> Result<(), DkgError> {
        let hash = p.hash()?;
        let idx = p.index();

        if self.is_bad(idx) {
            // Already misbehaved before
            return Ok(());
        }

        if let Some(prev) = self.vals.get(&idx) {
            if prev.hash()? != hash {
                // Bad behavior - we evict
                let _ = self.vals.remove(&idx);
                self.bad.push(idx);
            }
            // Same packet just rebroadcasted - all good
            return Ok(());
        }
        let _ = self.vals.insert(idx, p);

        Ok(())
    }

    fn is_bad(&self, idx: Index) -> bool {
        self.bad.iter().any(|i| *i == idx)
    }

    fn take(&mut self) -> Vec<P> {
        std::mem::take(&mut self.vals).into_values().collect()
    }

    fn len(&self) -> usize {
        self.vals.len()
    }
}

#[derive(Clone)]
pub enum Bundle<S: Scheme> {
    Deal(DealBundle<S>),
    Response(ResponseBundle),
    Justification(JustificationBundle<S>),
}

impl<S: Scheme> Display for Bundle<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Bundle::Deal(_) => f.write_str("Deal"),
            Bundle::Response(_) => f.write_str("Response"),
            Bundle::Justification(_) => f.write_str("Justification"),
        }
    }
}
