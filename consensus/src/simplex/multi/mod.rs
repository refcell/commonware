//! Multi-leader simplex: one leader per lane in every view.
//!
//! A multi-leader engine orders several independent chains (lanes) with one
//! validator set. Every lane slot `(view, lane)` runs the simplex vote flow with
//! its own certificates (signed under a lane-specific namespace), and all lanes
//! share one view number: a validator enters view `v+1` once every lane has a
//! certificate for view `v` or higher. A faulty lane leader therefore only
//! nullifies its own slot while the other lanes finalize.

mod gate;
pub use gate::{Gate, LaneId, ViewClock};

mod engine;
pub use engine::{Config, Engine, Lane, LaneActivity, LaneLeaders, Tagged, lane_namespace};
