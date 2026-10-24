//! Deterministic tests for the multi-leader engine.
//!
//! Included from `simplex::tests` to reuse its simulated-network helpers.

use super::*;
use crate::simplex::{
    elector::LaneOffset,
    multi::{self, LaneActivity, LaneId},
};
use commonware_actor::Feedback;

type LaneReporter = mocks::reporter::Reporter<
    deterministic::Context,
    ed25519::Scheme,
    LaneOffset<RoundRobin>,
    Sha256Digest,
>;

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

/// Leader index of `lane` in `view` (matches the engine's lane elector).
fn lane_leader(participants: &Set<PublicKey>, epoch: Epoch, view: View, lane: LaneId) -> usize {
    let elector = elector::Config::<ed25519::Scheme>::build(
        LaneOffset::new(RoundRobin::<Sha256>::default(), u32::from(lane)),
        participants,
    );
    usize::from(elector.elect(Round::new(epoch, view), ()))
}

/// Runs `n` validators over `lanes` lanes, with the validators in `offline`
/// never started, until every lane of every online validator has finalized
/// `required` views. Returns per-validator, per-lane reporters of the online
/// validators, their view clocks, and the participant set to `check`.
fn run<C>(seed: u64, n: u32, lanes: u16, offline: &[usize], required: View, check: C)
where
    C: FnOnce(&[Vec<LaneReporter>], &[multi::ViewClock], &Set<PublicKey>) + Send + 'static,
{
    let namespace = b"multi_leader".to_vec();
    let epoch = Epoch::new(333);
    let executor = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(600))),
    );
    let offline = offline.to_vec();
    executor.start(|mut context| async move {
        let Fixture {
            participants,
            private_keys,
            ..
        } = ed25519::fixture(&mut context, &namespace, n);
        let set: Set<PublicKey> = participants.clone().try_into().unwrap();
        let mut oracle =
            start_test_network_with_peers(context.child("network"), participants.clone(), true)
                .await;
        let mut registrations = register_validators(&mut oracle, &participants).await;
        let link = Link {
            latency: Duration::from_millis(50),
            jitter: Duration::from_millis(5),
            success_rate: probability!(1.0),
        };
        link_validators(&mut oracle, &participants, Action::Link(link), None).await;

        // One relay per lane: lanes are independent chains.
        let relays: Vec<_> = (0..lanes)
            .map(|_| Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new()))
            .collect();

        let mut all_reporters = Vec::new();
        let mut clocks = Vec::new();
        for (idx, validator) in participants.iter().enumerate() {
            if offline.contains(&idx) {
                continue;
            }
            let context = context
                .child("validator")
                .with_attribute("public_key", validator);
            let mut lane_cfgs = Vec::new();
            let mut reporters = Vec::new();
            for lane in 0..lanes {
                let scheme = ed25519::Scheme::signer(
                    &multi::lane_namespace(&namespace, lane),
                    set.clone(),
                    private_keys[idx].clone(),
                )
                .expect("participant");
                reporters.push(LaneReporter::new(
                    context.child("reporter").with_attribute("lane", lane),
                    mocks::reporter::Config {
                        participants: set.clone(),
                        scheme: scheme.clone(),
                        elector: LaneOffset::new(RoundRobin::<Sha256>::default(), u32::from(lane)),
                    },
                ));
                let (actor, application) = mocks::application::Application::new(
                    context.child("application").with_attribute("lane", lane),
                    mocks::application::Config::<Sha256, _> {
                        relay: relays[lane as usize].clone(),
                        me: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                        certify_latency: (10.0, 5.0),
                        should_certify: mocks::application::Certifier::Always,
                    },
                );
                actor.start();
                lane_cfgs.push(multi::Lane {
                    scheme,
                    automaton: application.clone(),
                    relay: application,
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                });
            }
            let cfg = multi::Config {
                lanes: lane_cfgs,
                elector: RoundRobin::<Sha256>::default(),
                reporter: Demux {
                    lanes: reporters.clone(),
                },
                blocker: oracle.control(validator.clone()),
                strategy: Sequential,
                partition: validator.to_string(),
                epoch,
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
            clocks.push(engine.clock());
            let (vote, certificate, resolver) = registrations
                .remove(validator)
                .expect("validator should be registered");
            engine.start(vote, certificate, resolver);
            all_reporters.push(reporters);
        }

        // Wait until every lane of every online validator finalized `required`.
        let mut waiters = Vec::new();
        for reporters in all_reporters.iter() {
            for reporter in reporters.iter() {
                let mut reporter = reporter.clone();
                waiters.push(context.child("waiter").spawn(move |_| async move {
                    let (mut latest, mut monitor) = reporter.subscribe().await;
                    while latest < required {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
        }
        join_all(waiters).await;
        check(&all_reporters, &clocks, &set);
    });
}

/// Asserts no faults, no invalid messages, and at most one finalized payload per slot
/// across all validators.
fn assert_safe(reporters: &[Vec<LaneReporter>], lanes: u16) {
    for lane in 0..lanes as usize {
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

#[test_traced]
fn test_multi_leader_all_online() {
    let lanes = 3;
    let required = View::new(30);
    run(0, 4, lanes, &[], required, move |reporters, clocks, _| {
    assert_safe(reporters, lanes);

    // All lanes move in the same views and none of them is ever nullified.
    for validator in reporters.iter() {
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
fn test_multi_leader_crashed_validator_stalls_only_its_lane_slots() {
    let lanes = 3;
    let n = 4;
    let crashed = 3;
    let required = View::new(30);
    run(1, n, lanes, &[crashed], required, move |reporters, _, participants| {
    assert_safe(reporters, lanes);

    let epoch = Epoch::new(333);
    let mut crashed_slots = 0;
    for validator in reporters.iter() {
        for view in View::range(View::new(2), View::new(25)) {
            for lane in 0..lanes {
                let leader = lane_leader(participants, epoch, view, lane);
                let reporter = &validator[lane as usize];
                if leader == crashed {
                    // The crashed leader's slot is nullified and never notarized.
                    crashed_slots += 1;
                    assert!(
                        reporter.nullifications.lock().contains_key(&view),
                        "lane {lane} view {view}: crashed leader slot not nullified"
                    );
                    assert!(
                        !reporter.notarizations.lock().contains_key(&view),
                        "lane {lane} view {view}: crashed leader slot notarized"
                    );
                } else {
                    // Every other lane makes progress in the same view.
                    assert!(
                        reporter.notarizations.lock().contains_key(&view),
                        "lane {lane} view {view}: live leader slot not notarized"
                    );
                }
            }
        }
    }
    assert!(crashed_slots > 0);
    });
}
