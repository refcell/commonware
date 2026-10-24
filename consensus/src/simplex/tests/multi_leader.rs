//! Deterministic tests for the multi-leader engine.
//!
//! A child of `simplex::tests` to reuse its simulated-network helpers.

use super::*;
use crate::{
    Automaton, CertifiableAutomaton,
    simplex::{
        elector::LaneOffset,
        multi::{self, LaneActivity, LaneId},
    },
};
use commonware_actor::Feedback;
use commonware_runtime::Handle;

const NAMESPACE: &[u8] = b"multi_leader";
const EPOCH: Epoch = Epoch::new(333);

type LaneReporter = mocks::reporter::Reporter<
    deterministic::Context,
    ed25519::Scheme,
    LaneOffset<RoundRobin>,
    Sha256Digest,
>;
type App = mocks::application::Mailbox<Sha256Digest, PublicKey>;

/// Routes each lane's activity to that lane's mock reporter.
#[derive(Clone)]
struct Demux {
    lanes: Vec<LaneReporter>,
}

impl crate::Reporter for Demux {
    type Activity = LaneActivity<ed25519::Scheme, Sha256Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.lanes[activity.lane as usize].report(activity.activity)
    }
}

/// Wraps an automaton and, when `silent`, never produces a proposal: a lane
/// leader that is alive (votes on everything) but fails to lead its lane.
#[derive(Clone)]
struct Silent {
    inner: App,
    silent: bool,
}

impl Automaton for Silent {
    type Context = <App as Automaton>::Context;
    type Digest = Sha256Digest;

    fn propose(
        &mut self,
        context: Self::Context,
    ) -> impl Future<Output = oneshot::Receiver<Self::Digest>> + Send {
        let inner = (!self.silent).then(|| self.inner.propose(context));
        #[allow(clippy::async_yields_async)]
        async move {
            match inner {
                Some(proposal) => proposal.await,
                None => oneshot::channel().1,
            }
        }
    }

    fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> impl Future<Output = oneshot::Receiver<bool>> + Send {
        self.inner.verify(context, payload)
    }
}

impl CertifiableAutomaton for Silent {
    fn certify(
        &mut self,
        round: Round,
        payload: Self::Digest,
    ) -> impl Future<Output = oneshot::Receiver<bool>> + Send {
        self.inner.certify(round, payload)
    }
}

/// Leader index of `lane` in `view`.
fn lane_leader(participants: &Set<PublicKey>, view: View, lane: LaneId) -> usize {
    let leaders = multi::LaneLeaders::<ed25519::Scheme, _>::new(
        RoundRobin::<Sha256>::default(),
        participants,
        3,
    );
    usize::from(leaders.leader(Round::new(EPOCH, view), lane).expect("scheduled"))
}

/// Simulated network shared by all validators of a test.
struct Net {
    oracle: Oracle<PublicKey, deterministic::Context>,
    participants: Vec<PublicKey>,
    private_keys: Vec<PrivateKey>,
    set: Set<PublicKey>,
    relays: Vec<Arc<mocks::relay::Relay<Sha256Digest, PublicKey>>>,
}

impl Net {
    async fn new(context: &mut deterministic::Context, n: u32, lanes: u16) -> Self {
        let Fixture {
            participants,
            private_keys,
            ..
        } = ed25519::fixture(context, NAMESPACE, n);
        let set: Set<PublicKey> = participants.clone().try_into().unwrap();
        let mut oracle =
            start_test_network_with_peers(context.child("network"), participants.clone(), true)
                .await;
        let link = Link {
            latency: Duration::from_millis(50),
            jitter: Duration::from_millis(5),
            success_rate: probability!(1.0),
        };
        link_validators(&mut oracle, &participants, Action::Link(link), None).await;
        // One relay per lane: lanes are independent chains.
        let relays = (0..lanes)
            .map(|_| Arc::new(mocks::relay::Relay::new()))
            .collect();
        Self {
            oracle,
            participants,
            private_keys,
            set,
            relays,
        }
    }

    /// Starts validator `idx` on all lanes; `silent` lanes never get a proposal from it.
    async fn start(
        &mut self,
        context: &deterministic::Context,
        idx: usize,
        silent: &[LaneId],
    ) -> (Handle<()>, Vec<LaneReporter>, multi::ViewClock) {
        let validator = self.participants[idx].clone();
        let context = context
            .child("validator")
            .with_attribute("public_key", &validator);
        let mut lanes = Vec::new();
        let mut reporters = Vec::new();
        for (lane, relay) in self.relays.iter().enumerate() {
            let lane = lane as LaneId;
            let scheme = ed25519::Scheme::signer(
                &multi::lane_namespace(NAMESPACE, lane),
                self.set.clone(),
                self.private_keys[idx].clone(),
            )
            .expect("participant");
            reporters.push(LaneReporter::new(
                context.child("reporter").with_attribute("lane", lane),
                mocks::reporter::Config {
                    participants: self.set.clone(),
                    scheme: scheme.clone(),
                    elector: LaneOffset::new(RoundRobin::<Sha256>::default(), u32::from(lane)),
                },
            ));
            let (actor, application) = mocks::application::Application::new(
                context.child("application").with_attribute("lane", lane),
                mocks::application::Config::<Sha256, _> {
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                },
            );
            actor.start();
            lanes.push(multi::Lane {
                scheme,
                automaton: Silent {
                    inner: application.clone(),
                    silent: silent.contains(&lane),
                },
                relay: application,
                floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(EPOCH)),
            });
        }
        let cfg = multi::Config {
            lanes,
            elector: RoundRobin::<Sha256>::default(),
            reporter: Demux {
                lanes: reporters.clone(),
            },
            blocker: self.oracle.control(validator.clone()),
            strategy: Sequential,
            partition: validator.to_string(),
            epoch: EPOCH,
            mailbox_size: NZUsize!(1024),
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_millis(1500),
            timeout_retry: Duration::from_secs(5),
            fetch_timeout: Duration::from_secs(1),
            view_retention: ViewDelta::new(10),
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            forward: ForwardPolicy::Disabled,
            track_historical_votes: false,
        };
        let engine = multi::Engine::new(context.child("engine"), cfg);
        let clock = engine.clock();
        let (vote, certificate, resolver) = register_validator(&mut self.oracle, validator).await;
        let handle = engine.start(vote, certificate, resolver);
        (handle, reporters, clock)
    }
}

/// Waits until every given reporter has finalized `required`.
async fn wait_finalized(context: &deterministic::Context, reporters: &[LaneReporter], required: View) {
    let mut waiters = Vec::new();
    for reporter in reporters {
        let mut reporter = reporter.clone();
        waiters.push(context.child("waiter").spawn(move |_| async move {
            let (mut latest, mut monitor) = reporter.subscribe().await;
            while latest < required {
                latest = monitor.recv().await.expect("event missing");
            }
        }));
    }
    join_all(waiters).await;
}

/// Asserts no faults, no invalid messages, and at most one finalized payload
/// per lane slot across all reporters (indexed `[validator][lane]`).
fn assert_safe(reporters: &[Vec<LaneReporter>]) {
    let lanes = reporters[0].len();
    for lane in 0..lanes {
        let mut finalized: HashMap<View, Sha256Digest> = HashMap::new();
        for validator in reporters {
            let reporter = &validator[lane];
            reporter.assert_no_faults();
            reporter.assert_no_invalid();
            for (view, (finalization, _)) in reporter.finalizations.lock().iter() {
                let payload = finalization.proposal.payload;
                if let Some(existing) = finalized.insert(*view, payload) {
                    assert_eq!(existing, payload, "lane {lane} forked at view {view}");
                }
            }
        }
    }
}

fn runner(seed: u64) -> deterministic::Runner {
    deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(600))),
    )
}

/// Asserts that in `views`, every slot led by a validator in `faulty` (on a
/// lane in `faulty_lanes`) is nullified and not notarized, and every other
/// slot is notarized.
fn assert_only_faulty_slots_stall(
    reporters: &[Vec<LaneReporter>],
    set: &Set<PublicKey>,
    views: (View, View),
    faulty: usize,
    faulty_lanes: &[LaneId],
) -> usize {
    let mut stalled = 0;
    for validator in reporters {
        for view in View::range(views.0, views.1) {
            for (lane, reporter) in validator.iter().enumerate() {
                let lane = lane as LaneId;
                let faulty_slot =
                    lane_leader(set, view, lane) == faulty && faulty_lanes.contains(&lane);
                let notarized = reporter.notarizations.lock().contains_key(&view);
                if faulty_slot {
                    stalled += 1;
                    assert!(
                        reporter.nullifications.lock().contains_key(&view),
                        "lane {lane} view {view}: faulty slot not nullified"
                    );
                    assert!(!notarized, "lane {lane} view {view}: faulty slot notarized");
                } else {
                    assert!(notarized, "lane {lane} view {view}: live slot not notarized");
                }
            }
        }
    }
    stalled
}

#[test_traced]
fn test_multi_leader_all_online() {
    let required = View::new(30);
    runner(0).start(|mut context| async move {
        let mut net = Net::new(&mut context, 4, 3).await;
        let mut all = Vec::new();
        let mut clocks = Vec::new();
        for idx in 0..4 {
            let (_, reporters, clock) = net.start(&context, idx, &[]).await;
            all.push(reporters);
            clocks.push(clock);
        }
        wait_finalized(&context, &all.concat(), required).await;
        assert_safe(&all);

        // All lanes move in the same views and none of them is ever nullified.
        for validator in all.iter() {
            for (lane, reporter) in validator.iter().enumerate() {
                let notarizations = reporter.notarizations.lock();
                for view in View::range(View::new(1), required) {
                    assert!(
                        notarizations.contains_key(&view),
                        "lane {lane} missing notarization at view {view}"
                    );
                }
                assert!(
                    reporter.nullifications.lock().is_empty(),
                    "lane {lane} nullified a view with all validators online"
                );
            }
        }
        for clock in clocks {
            assert!(clock.current() >= required);
        }
    });
}

#[test_traced]
fn test_multi_leader_crashed_validator_stalls_only_its_slots() {
    let crashed = 3;
    runner(1).start(|mut context| async move {
        let mut net = Net::new(&mut context, 4, 3).await;
        let mut all = Vec::new();
        for idx in 0..3 {
            all.push(net.start(&context, idx, &[]).await.1);
        }
        wait_finalized(&context, &all.concat(), View::new(30)).await;
        assert_safe(&all);
        let stalled = assert_only_faulty_slots_stall(
            &all,
            &net.set,
            (View::new(2), View::new(25)),
            crashed,
            &[0, 1, 2],
        );
        assert!(stalled > 0);
    });
}

#[test_traced]
fn test_multi_leader_silent_lane_leader_stalls_only_that_lane() {
    // Validator 0 votes on every lane and leads lanes 0 and 2 normally, but never
    // proposes on lane 1.
    let faulty = 0;
    runner(2).start(|mut context| async move {
        let mut net = Net::new(&mut context, 4, 3).await;
        let mut all = Vec::new();
        for idx in 0..4 {
            let silent: &[LaneId] = if idx == faulty { &[1] } else { &[] };
            all.push(net.start(&context, idx, silent).await.1);
        }
        wait_finalized(&context, &all.concat(), View::new(30)).await;
        assert_safe(&all);
        let stalled = assert_only_faulty_slots_stall(
            &all,
            &net.set,
            (View::new(2), View::new(25)),
            faulty,
            &[1],
        );
        assert!(stalled > 0);
    });
}

#[test_traced]
fn test_multi_leader_restarted_validator_rejoins() {
    let restarted = 2;
    runner(3).start(|mut context| async move {
        let mut net = Net::new(&mut context, 4, 3).await;
        let mut handles = Vec::new();
        let mut all = Vec::new();
        for idx in 0..4 {
            let (handle, reporters, _) = net.start(&context, idx, &[]).await;
            handles.push(handle);
            all.push(reporters);
        }
        wait_finalized(&context, &all.concat(), View::new(10)).await;

        // Crash one validator, let the others run without it, then restart it
        // from its journals.
        let handle = handles.remove(restarted);
        handle.abort();
        let _ = handle.await;
        context.sleep(Duration::from_secs(10)).await;
        let (_, reporters, clock) = net.start(&context, restarted, &[]).await;
        all.push(reporters);

        // Every lane of every validator, including the restarted one, keeps
        // finalizing, and the restarted validator rejoins the shared view.
        // The crashed instance's reporters stop at the crash; wait on the others.
        let live: Vec<_> = all
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx != restarted)
            .flat_map(|(_, reporters)| reporters.iter().cloned())
            .collect();
        wait_finalized(&context, &live, View::new(40)).await;
        assert_safe(&all);
        assert!(clock.current() >= View::new(40));
    });
}

#[test]
fn test_lane_leaders_are_distinct_and_rotate() {
    let Fixture { participants, .. } = ed25519::fixture(&mut test_rng(), NAMESPACE, 4);
    let set: Set<PublicKey> = participants.try_into().unwrap();
    let leaders =
        multi::LaneLeaders::<ed25519::Scheme, _>::new(RoundRobin::<Sha256>::default(), &set, 3);
    for view in View::range(View::new(1), View::new(20)) {
        let round = Round::new(EPOCH, view);
        let base = leaders.leader(round, 0).unwrap().get();
        for lane in 0..3u16 {
            let leader = leaders.leader(round, lane).unwrap().get();
            assert_eq!(leader, (base + u32::from(lane)) % 4);
        }
        let next = leaders.leader(Round::new(EPOCH, view.next()), 0).unwrap().get();
        assert_eq!(next, (base + 1) % 4);
    }
}
