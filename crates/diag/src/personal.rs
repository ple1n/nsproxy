use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersonalRuntimeState {
    pub llamacpp_task_pgid: Option<u32>,
    pub cinny_task_pgid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PersonalDaemonRequest {
    GetState,
    SetState(PersonalRuntimeState),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PersonalDaemonEvent {
    State(PersonalRuntimeState),
}
