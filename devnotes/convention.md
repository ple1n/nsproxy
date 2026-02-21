(agent: do not modify)

This is a utility for system-wide, Qubes like containerization engine but built on kernel namespaces. 

The tool provides medium-effort security against casual attackers.

# State handling

- All persited state are currently in json files at a state root by PERSIST_ROOT
- PersistentState is a trait that handles all state file loading saving
- command `sp state-root` prints all state visaulized on a tree. See crates/nsproxy-core/src/state_blueprint.rs 
- State is centralized at one place, which is part of the philosophy of nsproxy.

`sp X` refers to commands which can be found at `MainCommand::X`. `sp` is installed to user system as a SUID symlinked binary.

# State machine model 

Many things in the project follow a state machine model such as `PathExpansionState`. A state object is kept for the sole purpose of saving amount of arguments passed per function call. 

# Async + egui 

The main state handling in ui is async primitives from flume or crossbeam or tokio, plus recving per render pass. 

Compuation within render pass is to be avoided. 

# UplinkHub

All traffic got from TUN are routed through a routing function, which can be changed freely, as a field of `UplinkHub`. The hub handles all affairs about uplink proxies, 

Some proxies such as Clash proxies are usually supplied in the form of domain names, which need to be resolved periodically, as service supplier may change nodes. Resolution itself should go through uplinkhub. 

`sp serve` instruments a single container. There is `DiagEvent` infrastructure tracking all connections already. 

The GUI is built to be parallel to the CLI infra. That is the GUI should not depend on CLI and should perform many functonality through code in the GUI codebase directly. 

UplinkHub itself is not directly persistented. It's an aggregate struct built from other persisted state.