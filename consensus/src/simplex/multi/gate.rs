//! Shared view clock that keeps the lanes of a multi-leader engine in the same view.
//!
//! Each lane publishes the view it wants to enter (the view an independent simplex
//! instance would enter after observing a certificate). The shared view is the
//! minimum wanted view over all lanes, so a validator enters view `v+1` only once
//! every lane has a certificate for view `v` (or higher).

use crate::types::View;
use commonware_utils::{channel::watch, sync::Mutex};
use std::sync::Arc;

/// Index of a lane (one chain ordered by the shared consensus).
pub type LaneId = u16;

/// Shared view clock for all lanes of one validator.
#[derive(Clone)]
pub struct ViewClock {
    wanted: Arc<Mutex<Vec<View>>>,
    current: Arc<watch::Sender<View>>,
}

impl ViewClock {
    /// Creates a clock for `lanes` lanes, all starting in view 1.
    ///
    /// # Panics
    ///
    /// Panics if `lanes` is zero.
    pub fn new(lanes: u16) -> Self {
        assert!(lanes > 0, "at least one lane is required");
        let first = View::new(1);
        let (current, _) = watch::channel(first);
        Self {
            wanted: Arc::new(Mutex::new(vec![first; lanes as usize])),
            current: Arc::new(current),
        }
    }

    /// Returns the number of lanes.
    pub fn lanes(&self) -> u16 {
        self.wanted.lock().len() as u16
    }

    /// Returns the shared view: the minimum wanted view over all lanes.
    pub fn current(&self) -> View {
        *self.current.borrow()
    }

    /// Returns the view `lane` wants to enter.
    pub fn wanted(&self, lane: LaneId) -> View {
        self.wanted.lock()[lane as usize]
    }

    /// Subscribes to changes of the shared view.
    pub fn subscribe(&self) -> watch::Receiver<View> {
        self.current.subscribe()
    }

    /// Returns the gate for `lane`.
    ///
    /// # Panics
    ///
    /// Panics if `lane` is not below [`Self::lanes`].
    pub fn gate(&self, lane: LaneId) -> Gate {
        assert!(lane < self.lanes(), "lane out of range");
        Gate {
            clock: self.clone(),
            lane,
        }
    }

    /// Records that `lane` wants to enter `view` and returns the shared view.
    fn want(&self, lane: LaneId, view: View) -> View {
        let mut wanted = self.wanted.lock();
        let slot = &mut wanted[lane as usize];
        if view > *slot {
            *slot = view;
            let min = *wanted.iter().min().expect("at least one lane");
            self.current.send_if_modified(|current| {
                if min > *current {
                    *current = min;
                    true
                } else {
                    false
                }
            });
        }
        *self.current.borrow()
    }
}

/// One lane's handle on a [`ViewClock`].
#[derive(Clone)]
pub struct Gate {
    clock: ViewClock,
    lane: LaneId,
}

impl Gate {
    /// Returns the lane this gate belongs to.
    pub const fn lane(&self) -> LaneId {
        self.lane
    }

    /// Records the view this lane wants to enter and returns the shared view.
    pub(crate) fn want(&self, view: View) -> View {
        self.clock.want(self.lane, view)
    }

    /// Returns the view this lane wants to enter.
    pub(crate) fn wanted(&self) -> View {
        self.clock.wanted(self.lane)
    }

    /// Subscribes to changes of the shared view.
    pub(crate) fn subscribe(&self) -> watch::Receiver<View> {
        self.clock.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_view_is_minimum_wanted() {
        let clock = ViewClock::new(3);
        let (a, b, c) = (clock.gate(0), clock.gate(1), clock.gate(2));
        assert_eq!(clock.current(), View::new(1));
        assert_eq!(a.want(View::new(2)), View::new(1));
        assert_eq!(b.want(View::new(3)), View::new(1));
        assert_eq!(c.want(View::new(2)), View::new(2));
        assert_eq!(a.want(View::new(4)), View::new(2));
        assert_eq!(c.want(View::new(5)), View::new(3));
        assert_eq!(clock.current(), View::new(3));
        assert_eq!(b.wanted(), View::new(3));
    }

    #[test]
    fn wanted_view_never_decreases() {
        let clock = ViewClock::new(1);
        let gate = clock.gate(0);
        assert_eq!(gate.want(View::new(5)), View::new(5));
        assert_eq!(gate.want(View::new(3)), View::new(5));
        assert_eq!(gate.wanted(), View::new(5));
    }

    #[test]
    fn subscribers_observe_advances() {
        let clock = ViewClock::new(2);
        let mut rx = clock.subscribe();
        clock.gate(0).want(View::new(2));
        assert!(!rx.has_changed().unwrap());
        clock.gate(1).want(View::new(2));
        assert!(rx.has_changed().unwrap());
        assert_eq!(*rx.borrow_and_update(), View::new(2));
    }
}
