use std::{
    collections::{BTreeMap, BinaryHeap, VecDeque},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use backtrace::Backtrace;
use crossbeam::queue::SegQueue;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

pub mod summary;

/// Interactive Diagnostic protocol for nsproxy

pub struct DiagParams {
    port: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixTime {
    elapsed: Duration,
}

/// Instance
pub struct Diag {
    /// Not pruned in anyway, supposed to store one sessions' log
    log: Option<SegQueue<Item>>,
}

#[derive(Serialize, Deserialize)]
pub struct Item {
    time: UnixTime,
    bt: Backtrace,
    text: Content
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub enum Content {
    Text(String),
}   

pub struct DiagArc {
    diag: Arc<Diag>,
}

pub enum DiagProtoClient {
    Begin(UnixTime),
    End,
}

pub struct DiagProtoServer {
    diag: BinaryHeap<Item>,
    begin: Instant,
}

impl Ord for Item {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.time.cmp(&other.time)
    }
}

impl PartialOrd for Item {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.time.partial_cmp(&other.time)
    }
}

impl PartialEq for Item {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time && self.text == other.text
    }
}

impl Eq for Item {}

/// For simplicity, this uses TCP
pub async fn listen(params: &DiagParams) -> Result<DiagArc> {
    let diag = DiagArc {
        diag: Arc::new(Diag { log: None }),
    };
    let listener = TcpListener::bind(format!("127.0.0.1:{}", params.port)).await?;

    Ok(diag)
}

impl Diag {
    pub fn trace(&self, text: Content) {
        if let Some(log) = &self.log {
            log.push(Item {
                time: UnixTime {
                    elapsed: SystemTime::now().duration_since(UNIX_EPOCH).unwrap(),
                },
                bt: Backtrace::new(),
                text,
            });
        }
    }
}
