//! Periodically writes a summary to a local file
//! The main concern is that some computation is blocking the async executor or reducing the 'accept' rate
//! which should be traced here
//! 

use std::collections::HashMap;

use crossbeam::queue::SegQueue;

use crate::{Item, UnixTime};

#[derive(Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TracePoints {
    TUNAccept,
    DNSLock
}

struct Stats {
    logs: HashMap<TracePoints, TimerSeries>
}

struct TimerSeries {
    log: SegQueue<Item>
}

struct Overview {
    max: UnixTime,
    avg: UnixTime,
    min: UnixTime
}