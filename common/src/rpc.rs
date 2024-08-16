use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum FromClient {
    ID {
        name: Option<String>,
        edge: Option<usize>,
    },
    Data(Data),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum FromServer {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Data {
    LoopTime(Duration),
}

pub const TMP_RPC_PATH: &str = "nsproxy";
