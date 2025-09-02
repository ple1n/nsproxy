/// This binary will at most spawn 2 processes (including itself)
/// It's intended to be minimal, which can be used later in higher order composition such as in GUI
use clap::{
    Parser, Subcommand, ValueEnum,
    builder::{TypedValueParser, ValueParser, ValueParserFactory},
};
use nix::unistd::Pid;
use nsproxy_common::{ExactNS, NSFrom};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};
use tun2socks5::ArgMode;

/// NSProxy V3
/// Manage netns redirection with SOCKS5 proxy configuration
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Working state directory
    #[arg(short, long, default_value = "./")]
    output: PathBuf,
    /// Source network namespace (src=/path OR src=1234)
    #[arg(long)]
    src: NsInput,
    /// Target network namespace (dst=/path OR dst=1234)
    #[arg(long)]
    dst: NsInput,

    #[command(subcommand)]
    proxy: Option<ArgMode>,
    /// Make veths (optional name, default "veth0")
    #[arg(long, value_name = "NAME", default_missing_value = "veth0")]
    veth: Option<Option<String>>,
    /// change uid after entering shell
    #[arg(short, long)]
    uid: Option<u32>,
}

/// Representation of a namespace input (PID or Path)
#[derive(Debug, Serialize, Deserialize, Clone)]
enum NsInput {
    Pid(i32),
    Path(PathBuf),
    /// this process
    This,
}

impl std::str::FromStr for NsInput {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(pid) = s.parse::<i32>() {
            Ok(NsInput::Pid(pid))
        } else {
            Ok(NsInput::Path(PathBuf::from(s)))
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let state_dir = PathBuf::from("./nsproxy.state");
    fs::create_dir_all(&state_dir)?;
    let pid = nix::unistd::Pid::this();
    let src: ExactNS = NSFrom::from_source(cli.src.resolve(pid))?;
    let dst: ExactNS = NSFrom::from_source(cli.dst.resolve(pid))?;
    
    Ok(())
}

impl NsInput {
    pub fn resolve(self, this_pid: Pid) -> Self {
        match &self {
            NsInput::Pid(_) | NsInput::Path(_) => self,
            NsInput::This => NsInput::Pid(this_pid.as_raw()),
        }
    }
}

impl NSFrom<NsInput> for ExactNS {
    fn from_source(source: NsInput) -> anyhow::Result<Self> {
        match source {
            NsInput::Path(p) => NSFrom::from_source(p),
            NsInput::Pid(p) => NSFrom::from_source(p),
            NsInput::This => unreachable!()
        }
    }
}
