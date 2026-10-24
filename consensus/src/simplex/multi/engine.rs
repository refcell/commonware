use super::{LaneId, ViewClock};
use crate::{
    CertifiableAutomaton, Relay, Reporter,
    simplex::{
        Plan,
        config::{self, Floor, ForwardPolicy, SkipPolicy},
        elector::{self, LaneOffset},
        engine,
        scheme::Scheme,
        types::{Activity, Context},
    },
    types::{Epoch, ViewDelta},
};
use commonware_actor::Feedback;
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_p2p::{Blocker, Receiver, Sender, utils::mux::Muxer};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, Storage, buffer::paged::CacheRef, spawn_cell,
};
use futures::future::select_all;
use rand_core::CryptoRng;
use std::{num::NonZeroUsize, time::Duration};
use tracing::debug;

/// Signing namespace for `lane`, derived from a base namespace.
///
/// Every lane must sign under a distinct namespace so that votes and
/// certificates of one lane never verify as another lane's.
pub fn lane_namespace(base: &[u8], lane: LaneId) -> Vec<u8> {
    let mut namespace = Vec::with_capacity(base.len() + 8);
    namespace.extend_from_slice(base);
    namespace.extend_from_slice(b"_LANE_");
    namespace.extend_from_slice(&lane.to_be_bytes());
    namespace
}

/// A reporter event of one lane.
#[derive(Clone, Debug)]
pub struct LaneActivity<S: Scheme<D>, D: Digest> {
    /// Lane that produced the activity.
    pub lane: LaneId,
    /// The simplex activity of that lane.
    pub activity: Activity<S, D>,
}

/// Wraps a [`LaneActivity`] reporter so a lane engine can report plain activity.
#[derive(Clone)]
pub struct Tagged<F> {
    lane: LaneId,
    inner: F,
}

impl<S: Scheme<D>, D: Digest, F: Reporter<Activity = LaneActivity<S, D>>> Reporter for Tagged<F> {
    type Activity = Activity<S, D>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.inner.report(LaneActivity {
            lane: self.lane,
            activity,
        })
    }
}

/// Per-lane inputs of a multi-leader engine.
pub struct Lane<S: Scheme<D>, D: Digest, A, R> {
    /// Signing scheme for this lane, built with [`lane_namespace`].
    pub scheme: S,
    /// Application that proposes, verifies, and certifies this lane's blocks.
    pub automaton: A,
    /// Broadcasts this lane's proposed payloads.
    pub relay: R,
    /// Starting point of this lane (genesis payload or a finalization).
    pub floor: Floor<S, D>,
}

/// Configuration of a multi-leader engine.
///
/// Shared fields have the same meaning as in [`config::Config`]. The lane
/// engines use rotating terms and a disabled skip policy.
pub struct Config<S, L, B, D, A, R, F, T>
where
    S: Scheme<D>,
    D: Digest,
{
    /// Lanes, indexed by [`LaneId`]. Must be non-empty.
    pub lanes: Vec<Lane<S, D, A, R>>,
    /// Base leader election; lane `l` elects `base + l (mod n)`.
    pub elector: L,
    /// Receives the activity of every lane, tagged with its lane.
    pub reporter: F,
    pub blocker: B,
    pub strategy: T,
    /// Prefix of the per-lane journal partitions (`{partition}-lane-{l}`).
    pub partition: String,
    pub epoch: Epoch,
    pub mailbox_size: NonZeroUsize,
    pub leader_timeout: Duration,
    pub certification_timeout: Duration,
    pub timeout_retry: Duration,
    pub fetch_timeout: Duration,
    pub view_retention: ViewDelta,
    pub replay_buffer: NonZeroUsize,
    pub write_buffer: NonZeroUsize,
    pub page_cache: CacheRef,
    pub forward: ForwardPolicy,
    pub track_historical_votes: bool,
}

type LaneEngine<E, S, L, B, D, A, R, F, T> =
    engine::Engine<E, S, LaneOffset<L>, B, D, A, R, Tagged<F>, T>;

/// Multi-leader simplex engine: one simplex engine per lane, sharing a view clock.
pub struct Engine<
    E: Clock + CryptoRng + Spawner + Storage + Metrics,
    S: Scheme<D>,
    L: elector::Config<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: CertifiableAutomaton<Context = Context<D, S::PublicKey>, Digest = D>,
    R: Relay<Digest = D, PublicKey = S::PublicKey, Plan = Plan<S::PublicKey>>,
    F: Reporter<Activity = LaneActivity<S, D>>,
    T: Strategy,
> {
    context: ContextCell<E>,
    clock: ViewClock,
    mailbox_size: usize,
    #[allow(clippy::type_complexity)]
    lanes: Vec<LaneEngine<E, S, L, B, D, A, R, F, T>>,
}

impl<
    E: Clock + CryptoRng + Spawner + Storage + Metrics,
    S: Scheme<D>,
    L: elector::Config<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: CertifiableAutomaton<Context = Context<D, S::PublicKey>, Digest = D>,
    R: Relay<Digest = D, PublicKey = S::PublicKey, Plan = Plan<S::PublicKey>>,
    F: Reporter<Activity = LaneActivity<S, D>>,
    T: Strategy,
> Engine<E, S, L, B, D, A, R, F, T>
{
    /// Creates a multi-leader engine.
    ///
    /// # Panics
    ///
    /// Panics if there are no lanes, more than `u16::MAX` lanes, or the elector
    /// does not use rotating terms.
    pub fn new(context: E, cfg: Config<S, L, B, D, A, R, F, T>) -> Self {
        assert!(!cfg.lanes.is_empty(), "at least one lane is required");
        let count = u16::try_from(cfg.lanes.len()).expect("too many lanes");
        let clock = ViewClock::new(count);
        let mut lanes = Vec::with_capacity(cfg.lanes.len());
        for (index, lane) in cfg.lanes.into_iter().enumerate() {
            let id = index as LaneId;
            let lane_cfg = config::Config {
                scheme: lane.scheme,
                elector: LaneOffset::new(cfg.elector.clone(), u32::from(id)),
                blocker: cfg.blocker.clone(),
                automaton: lane.automaton,
                relay: lane.relay,
                reporter: Tagged {
                    lane: id,
                    inner: cfg.reporter.clone(),
                },
                track_historical_votes: cfg.track_historical_votes,
                strategy: cfg.strategy.clone(),
                partition: format!("{}-lane-{id}", cfg.partition),
                mailbox_size: cfg.mailbox_size,
                epoch: cfg.epoch,
                floor: lane.floor,
                replay_buffer: cfg.replay_buffer,
                write_buffer: cfg.write_buffer,
                page_cache: cfg.page_cache.clone(),
                leader_timeout: cfg.leader_timeout,
                certification_timeout: cfg.certification_timeout,
                timeout_retry: cfg.timeout_retry,
                view_retention: cfg.view_retention,
                skip: SkipPolicy::Disabled,
                fetch_timeout: cfg.fetch_timeout,
                forward: cfg.forward,
            };
            lanes.push(engine::Engine::new_gated(
                context.child("lane").with_attribute("lane", id),
                lane_cfg,
                Some(clock.gate(id)),
            ));
        }
        Self {
            context: ContextCell::new(context),
            clock,
            mailbox_size: cfg.mailbox_size.get(),
            lanes,
        }
    }

    /// Returns the shared view clock (for telemetry).
    pub fn clock(&self) -> ViewClock {
        self.clock.clone()
    }

    /// Starts every lane.
    ///
    /// Takes the same three channels as [`engine::Engine::start`]; lanes are
    /// multiplexed over each channel with subchannel = lane id.
    pub fn start<VS, VR, CS, CR, RS, RR>(
        mut self,
        vote_network: (VS, VR),
        certificate_network: (CS, CR),
        resolver_network: (RS, RR),
    ) -> Handle<()>
    where
        VS: Sender<PublicKey = S::PublicKey>,
        VR: Receiver<PublicKey = S::PublicKey>,
        CS: Sender<PublicKey = S::PublicKey>,
        CR: Receiver<PublicKey = S::PublicKey>,
        RS: Sender<PublicKey = S::PublicKey>,
        RR: Receiver<PublicKey = S::PublicKey>,
    {
        spawn_cell!(
            self.context,
            self.run(vote_network, certificate_network, resolver_network)
        )
    }

    async fn run<VS, VR, CS, CR, RS, RR>(
        self,
        vote_network: (VS, VR),
        certificate_network: (CS, CR),
        resolver_network: (RS, RR),
    ) where
        VS: Sender<PublicKey = S::PublicKey>,
        VR: Receiver<PublicKey = S::PublicKey>,
        CS: Sender<PublicKey = S::PublicKey>,
        CR: Receiver<PublicKey = S::PublicKey>,
        RS: Sender<PublicKey = S::PublicKey>,
        RR: Receiver<PublicKey = S::PublicKey>,
    {
        let context = self.context.into_present();
        let (vote_mux, mut vote_handle) = Muxer::new(
            context.child("vote_mux"),
            vote_network.0,
            vote_network.1,
            self.mailbox_size,
        );
        let (certificate_mux, mut certificate_handle) = Muxer::new(
            context.child("certificate_mux"),
            certificate_network.0,
            certificate_network.1,
            self.mailbox_size,
        );
        let (resolver_mux, mut resolver_handle) = Muxer::new(
            context.child("resolver_mux"),
            resolver_network.0,
            resolver_network.1,
            self.mailbox_size,
        );
        let mut vote_task = vote_mux.start();
        let mut certificate_task = certificate_mux.start();
        let mut resolver_task = resolver_mux.start();

        let mut lane_tasks = Vec::with_capacity(self.lanes.len());
        for (index, lane) in self.lanes.into_iter().enumerate() {
            let subchannel = index as u64;
            let vote = vote_handle
                .register(subchannel)
                .await
                .expect("vote subchannel");
            let certificate = certificate_handle
                .register(subchannel)
                .await
                .expect("certificate subchannel");
            let resolver = resolver_handle
                .register(subchannel)
                .await
                .expect("resolver subchannel");
            lane_tasks.push(lane.start(vote, certificate, resolver));
        }

        let mut shutdown = context.stopped();
        select! {
            _ = &mut shutdown => {
                debug!("context shutdown, stopping multi-leader engine");
            },
            (result, index, _) = select_all(lane_tasks) => {
                debug!(?result, lane = index, "lane stopped, shutting down multi-leader engine");
            },
            result = &mut vote_task => {
                debug!(?result, "vote muxer stopped, shutting down multi-leader engine");
            },
            result = &mut certificate_task => {
                debug!(?result, "certificate muxer stopped, shutting down multi-leader engine");
            },
            result = &mut resolver_task => {
                debug!(?result, "resolver muxer stopped, shutting down multi-leader engine");
            },
        }
    }
}
