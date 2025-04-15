use super::dkg::Config;
use super::dkg::DistKeyGenerator;
use super::dkg::DkgError;
use super::dkg::Phase;
use super::structs::*;
use crate::traits::Scheme;

use std::collections::HashMap;
use std::fmt::Display;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{debug, error, info, Span};

pub type BundleSender<T> = mpsc::Sender<Bundle<T>>;
pub type BundleReceiver<T> = mpsc::Receiver<Bundle<T>>;

/// Phaser must signal on its channel when the protocol should move to a next
/// phase. Phase must be sequential: DealPhase (start), ResponsePhase,
/// JustifPhase and then FinishPhase.
struct Phaser {
    new_phase: mpsc::Receiver<Phase>,
}

impl Phaser {
    fn init(phase_timeout: Duration) -> Self {
        let (tx, rx) = mpsc::channel::<Phase>(1);
        tokio::task::spawn(async move {
            let mut timeout = tokio::time::interval(phase_timeout);
            // first tick completes immediately
            timeout.tick().await;

            // errors are ignored - dkg protocol might finish before the phaser sends the Phase::Finish
            let _ = tx.send(Phase::Deal).await;
            timeout.tick().await;
            let _ = tx.send(Phase::Response).await;
            timeout.tick().await;
            let _ = tx.send(Phase::Justif).await;
            timeout.tick().await;
            let _ = tx.send(Phase::Finish).await;
        });

        Self { new_phase: rx }
    }
}

pub struct Protocol<S: Scheme> {
    dkg: DistKeyGenerator<S>,
    can_issue: bool,
    sendout: SendOut<S>,
}

impl<S: Scheme> Protocol<S> {
    pub fn new_dkg(c: Config<S>, sendout: SendOut<S>) -> Result<Self, DkgError> {
        let dkg = DistKeyGenerator::new(c)?;

        let p = Self {
            can_issue: dkg.can_issue,
            dkg,
            sendout,
        };

        Ok(p)
    }

    pub fn start(
        mut self,
        mut bundle_rx: BundleReceiver<S>,
    ) -> JoinHandle<Result<DkgOutput<S>, DkgError>> {
        let mut deals = Set::<DealBundle<S>>::new(self.log());
        let mut resps = Set::<ResponseBundle>::new(self.log());
        let mut _justifs = Set::<JustificationBundle<S>>::new(self.log());
        let new_n = self.dkg.c.new_nodes.len();
        let old_n = self.dkg.c.old_nodes.len();

        tokio::task::spawn(async move {
            let mut interval = Phaser::init(Duration::from_secs(10));
            loop {
                tokio::select! {
                    next_phase = interval.new_phase.recv()=>{ if let Some(phase) = next_phase {
                        match phase {
                            Phase::Deal =>{
                                info!(parent: self.log(), "phaser: moving to sending deals phase");
                                self.send_deals().await?;
                            },
                            Phase::Response =>{
                                info!(parent: self.log(), "phaser: moving to response phase, got {} deals", &deals.len());
                                self.to_resp(&mut deals).await?;
                            },
                            Phase::Justif =>{
                                info!(parent: self.log(), "phaser: moving to justifications phase, got {} resps", &resps.len());
                            },
                            Phase::Finish => todo!(),
                            Phase::Init => unreachable!(""),
                        }} else { return Err(DkgError::BUG_PhaserChannelClosed)}
                    }
                    new_bundle = bundle_rx.recv()=>{ if let Some(bundle)= new_bundle{
                        if let Err(err) = self.dkg.c.verify_bundle_signature(&bundle){
                            error!(parent: self.log(), "ignoring new {bundle}, reason: {err}");
                        } else {
                            match bundle {
                                Bundle::Deal(new_deal) =>{
                                    deals.push(new_deal)?;
                                    if deals.len() == old_n{
                                        info!(parent: self.log(), "newDeal: fast moving to response phase, got {old_n} deals");
                                            self.to_resp(&mut deals).await?
                                    }
                                }
                                Bundle::Response(new_resp) =>{
                                    resps.push(new_resp)?;
                                    if resps.len() == new_n{
                                        info!(parent: self.log(), "newResp: fast moving to justifications phase, got {new_n} resps");
                                        if self.phase() == Phase::Response{
                                            match self.to_just(&mut resps)?{
                                                Flow::DkgOutput(dkg_output) => {
                                                    break Ok(dkg_output);
                                                },
                                                Flow::Justification(_justification_bundle) => todo!(),
                                                Flow::Leaving => todo!(),
                                            }
                                        }
                                    }
                                },
                                Bundle::Justification(_just) => todo!(),
                            }
                        }} else { return Err(DkgError::BUG_BundleChannelClosed) }
                    }
                }
            }
        })
    }

    #[allow(clippy::wrong_self_convention)]
    async fn to_resp(&mut self, deals: &mut Set<DealBundle<S>>) -> Result<(), DkgError> {
        // for all dealers, we should be in the DealPhase
        if self.can_issue && self.phase() != Phase::Deal {
            return Ok(());
        }
        // for all *new* share holders, we should be in the InitPhase
        if !self.can_issue && self.phase() != Phase::Init {
            return Ok(());
        }
        self.send_responses(deals.take_values()).await
    }

    #[allow(clippy::wrong_self_convention)]
    fn to_just(&mut self, resps: &mut Set<ResponseBundle>) -> Result<Flow<S>, DkgError> {
        self.dkg.process_responses(&resps.take_values())
    }

    async fn send_deals(&mut self) -> Result<(), DkgError> {
        if !self.can_issue {
            return Ok(());
        }
        let bundle = self.dkg.deals()?;

        info!(parent: &self.dkg.c.log, "sendDeals, Sending out deal bundle {} deals",bundle.deals.len());
        self.sendout.push_deals(bundle).await
    }

    async fn send_responses(&mut self, deals: Vec<DealBundle<S>>) -> Result<(), DkgError> {
        let deals_len = deals.len();

        // a node that is only in the old group should not process deals
        if let Some(bundle) = self.dkg.process_deals(deals)? {
            info!(parent: &self.dkg.c.log, "sendResponses, sending out response bundle, from {deals_len} deals");
            self.sendout.push_responses(bundle).await?;
        }

        Ok(())
    }

    fn phase(&self) -> Phase {
        self.dkg.state
    }

    fn log(&self) -> &tracing::Span {
        &self.dkg.c.log
    }
}

struct Set<P: Packet> {
    vals: HashMap<Index, P>,
    bad: Vec<Index>,
    // TODO: remove the log
    log: Span,
}

impl<P: Packet> Set<P> {
    fn new(log: &Span) -> Self {
        Self {
            vals: HashMap::new(),
            bad: vec![],
            log: log.to_owned(),
        }
    }

    fn push(&mut self, p: P) -> Result<(), DkgError> {
        let hash = p.hash()?;
        let idx = p.index();

        if self.is_bad(idx) {
            // already misbehaved before
            return Ok(());
        }

        if let Some(prev) = self.vals.get(&idx) {
            if prev.hash()? != hash {
                // bad behavior - we evict
                let _ = self.vals.remove(&idx);
                self.bad.push(idx);
            }
            // same packet just rebroadcasted - all good
            return Ok(());
        }
        debug!(parent: &self.log, "set: added valid {p}, index: {}", p.index());
        let _ = self.vals.insert(idx, p);

        Ok(())
    }

    fn is_bad(&self, idx: Index) -> bool {
        self.bad.iter().any(|i| *i == idx)
    }

    fn take_values(&mut self) -> Vec<P> {
        std::mem::take(&mut self.vals).into_values().collect()
    }

    fn len(&self) -> usize {
        self.vals.len()
    }
}

pub struct SendOut<S: Scheme> {
    pub tx: mpsc::Sender<Bundle<S>>,
}

impl<S: Scheme> SendOut<S> {
    pub fn new() -> (Self, mpsc::Receiver<Bundle<S>>) {
        let (tx, rx) = mpsc::channel(1);
        (Self { tx }, rx)
    }

    async fn push_deals(&self, bundle: DealBundle<S>) -> Result<(), DkgError> {
        self.tx
            .send(Bundle::Deal(bundle))
            .await
            .map_err(|_| DkgError::BUG_SendOutClosed)
    }

    async fn push_responses(&self, bundle: ResponseBundle) -> Result<(), DkgError> {
        self.tx
            .send(Bundle::Response(bundle))
            .await
            .map_err(|_| DkgError::BUG_SendOutClosed)
    }

    async fn _push_justifications(&self, bundle: JustificationBundle<S>) -> Result<(), DkgError> {
        self.tx
            .send(Bundle::Justification(bundle))
            .await
            .map_err(|_| DkgError::BUG_SendOutClosed)
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
