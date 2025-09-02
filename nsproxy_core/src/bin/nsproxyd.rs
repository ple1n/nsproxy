/// This binary will at most spawn 2 processes (including itself)
/// It's intended to be minimal, which can be used later in higher order composition such as in GUI
use clap::{
    Parser, Subcommand, ValueEnum,
    builder::{TypedValueParser, ValueParser, ValueParserFactory},
};
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
    /// Working state directory. defaults to "./"
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

#[derive(Serialize, Deserialize, Clone, Debug, Parser)]
pub struct NsArg {
    #[arg(long)]
    path: Option<PathBuf>,

    #[arg(long)]
    pid: Option<i32>,
}

/// Representation of a namespace input (PID or Path)
#[derive(Debug, Serialize, Deserialize, Clone)]
enum NsInput {
    Pid(u32),
    Path(PathBuf),
}

impl std::str::FromStr for NsInput {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(pid) = s.parse::<u32>() {
            Ok(NsInput::Pid(pid))
        } else {
            Ok(NsInput::Path(PathBuf::from(s)))
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    dbg!(&cli.veth);
    // Ensure ./nsproxy.state exists
    let state_dir = PathBuf::from("./nsproxy.state");
    fs::create_dir_all(&state_dir)?;

    println!("State written to {:?}", cli.output);
    Ok(())
}
