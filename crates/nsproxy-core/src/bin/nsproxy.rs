#![feature(ip_as_octets)]

use capctl::prctl;
/// This binary will at most spawn 2 processes (including itself)
/// It's intended to be minimal, which can be used later in higher order composition such as in GUI
use clap::{
    CommandFactory, Parser, Subcommand, ValueEnum,
    builder::{TypedValueParser, ValueParser, ValueParserFactory},
};
use clap_complete::{generate, shells::Fish};
use futures::stream::{FuturesUnordered, TryStreamExt};
use futures::{
    AsyncWriteExt, SinkExt, StreamExt,
    channel::{
        mpsc::{self, unbounded},
        oneshot,
    },
    future::join_all,
};
use reqwest::redirect::Policy;
use socks5_impl::protocol::WireAddress;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as TokioWriteExt},
    time::sleep,
};

use futures_lite::future::block_on;
use hardware_address::MacAddr;
use ipnetwork::{IpNetwork, Ipv4Network};
use libc::KERN_HOTPLUG;
use nix::{
    mount::{MsFlags, mount as nix_mount},
    pty::openpty,
    sched::{CloneFlags, unshare},
    unistd::{
        ForkResult, Gid, Pid, Uid, chdir, chown, dup2, execve, fork, getresgid, getresuid, pipe,
        setsid,
        setgroups, setresgid, setresuid,
    },
};
use notify::{Event, EventKind, RecommendedWatcher, Watcher, event::ModifyKind};
use nsproxy_common::{ExactNS, NSFrom, NSSource, NamespacesRegistry, PidPath, ProfileNamespaces, UniqueFile, forever};
use nsproxy_core::{
    BasisCommand, Cli, HotConfig, MainCommand, NetlinkOps, NsproxyConfig, Paths, PathsBinds,
    SandboxMode, TemplateConfig, TunMaker,
    cmd_common::{
        apply_ns_env, check_proxy_mode, enter_ns, read_ns_alive, read_ns_alive_opt,
        report_clone3_err, update_ns_alive,
    },
    env::{ENV_NS, args_deduce_mount, name_to_mount_path},
    hot_reload::{VethIps, sync_links, watch_hot},
    sandbox::{apply_chmod, apply_mounts},
    shell::{ShellArgs, ShellPrefs},
    state_paths,
    sys::{
        Clone3Result, NSEnter, check_capsys, check_selfns, enable_ping_all, mount_bind,
        mount_bind_ro_explicit, mount_bind_root, mount_bind_rw_explicit, mount_ns,
        mount_nsswitch_conf, mount_resolv_conf, mount_tmpfs, pivot_root_into, rm_mount,
    },
    tokio_netlink_conn,
    utils::ToExactNs,
};
use nsproxy_core::{
    cmd_uplink::{cmd_uplink, load_saved_uplink_hub},
    env::{ENV_CONTAINER, ENV_PROFILE},
    *,
};
use owo_colors::OwoColorize;
use passfd::FdPassingExt;
use pidfd::PidFd;
use rtnetlink::packet_route::{
    AddressFamily,
    link::{LinkAttribute, LinkExtentMask, LinkFlags, LinkHeader},
};
use rtnetlink::{Handle, LinkMessageBuilder, LinkUnspec, LinkVeth};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque, hash_map::Entry},
    sync::Mutex,
    convert::Infallible,
    ffi::OsStr,
    fs::{self, Permissions},
    future::{pending, ready},
    io::{ErrorKind, Read, Write},
    mem::ManuallyDrop,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
        unix::{
            fs::{MetadataExt, PermissionsExt, symlink},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    pin::Pin,
    process::exit,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{select, sync};
use tracing::{error, info, level_filters::LevelFilter, warn};
use tracing_subscriber::{Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use tun2socks5::{
    ArgMode, IArgs, VirtDNSChange, aok, diag,
    dns::VirtDNSHandle,
    flume,
    ipstack::stream::{IpStackStream, IpStackTcpStream},
    tun_rs::AsyncDevice,
};

const PTY_SCROLLBACK_CAP: usize = 256 * 1024;
const PTY_BROADCAST_CAP: usize = 128;

fn main() -> anyhow::Result<()> {
    // Ignore SIGPIPE so logging to a closed pipe does not kill the daemon.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }

    // Fast path: `sp <fd_num>` — read a bincode-encoded `Cli` directly from the fd.
    // This lets callers (e.g. the GUI) pass structured args without string conversion.
    let mut cli = {
        let raw_args: Vec<String> = std::env::args().collect();
        if raw_args.len() == 2 {
            if let Ok(fd) = raw_args[1].parse::<i32>() {
                nsproxy_core::decode_cli_from_fd(fd)?
            } else {
                Cli::parse()
            }
        } else {
            Cli::parse()
        }
    };
    if let Some(root) = cli.root.clone() {
        state_paths::set_persist_root(root.clone());
        info!("Using state root: {:?}", root);
    }
    diag::set_protocol_version(nsproxy_core::build_identity());
    // DEBUG is annoying because its filled with TCP retransmission logs
    let (layer, reload_handle) = tracing_subscriber::reload::Layer::new(
        fmt::Layer::new()
            .without_time()
            .with_filter(LevelFilter::INFO),
    );
    // https://docs.rs/tracing-subscriber/latest/tracing_subscriber/layer/trait.Layer.html
    tracing_subscriber::registry()
        .with(layer)
        .with(diag::DiagTracingLayer)
        .init();

    let pid = nix::unistd::Pid::this();

    use rlimit as rl;
    let (soft, hard) = rl::Resource::NOFILE.get()?;
    if !matches!(&cli.cmd, MainCommand::Id { .. }) {
        info!(
            "open file limits, soft={}, hard={}. trying to raise soft limit to max",
            soft, hard
        );
    }
    rl::Resource::NOFILE.set(hard, hard)?;

    match cli.cmd {
        MainCommand::Socks5 { port } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                use socks5_impl::protocol::*;
                use socks5_impl::server::*;
                warn!("starting socks server on 0.0.0.0:{}", port);
                let addr = format!("0.0.0.0:{}", port);
                let server = Server::bind(addr.parse()?, Arc::new(auth::NoAuth)).await?;
                loop {
                    let (conn, _) = server.accept().await?;
                    tokio::spawn(async {
                        if let Err(err) = handle_socks5_connection(conn).await {
                            warn!("socks5 connection error: {}", err);
                        }
                    });
                }

                aok!()
            })?;
        }
        MainCommand::Rm { file } => {
            rm_mount(&file)?;
        }
        MainCommand::Id { pid } => {
            // Keep this command output clean and human-focused.
            let _ = reload_handle.modify(|k| *k.filter_mut() = LevelFilter::WARN);

            let env_value = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());
            let fmt_env = |v: Option<String>| v.unwrap_or_else(|| "-".to_string());

            let container = env_value(ENV_CONTAINER);
            let browser = env_value(ENV_PROFILE);
            let netns = env_value(ENV_NS);

            let target_pid = pid;
            let target_ns = if let Some(pid) = target_pid {
                Some(ProfileNamespaces {
                    mnt: ExactNS::from_source((PidPath::N(pid as i32), "mnt"))?,
                    net: ExactNS::from_source((PidPath::N(pid as i32), "net"))?,
                    pid: ExactNS::from_source((PidPath::N(pid as i32), "pid"))?,
                })
            } else {
                None
            };

            let self_ns = ProfileNamespaces {
                mnt: ExactNS::from_source((PidPath::Selfproc, "mnt"))?,
                net: ExactNS::from_source((PidPath::Selfproc, "net"))?,
                pid: ExactNS::from_source((PidPath::Selfproc, "pid"))?,
            };

            let print_divider = |widths: &[usize]| {
                print!("+");
                for &w in widths {
                    print!("{}+", "-".repeat(w + 2));
                }
                println!();
            };

            let status_width = "MISSING".len();

            println!("{}", "NSPROXY ID".bold().bright_cyan());
            println!(
                "{} {}={}  {}={}  {}={}",
                "env".bold().bright_black(),
                "container".bright_blue(),
                fmt_env(container.clone()).bright_white(),
                "browser".bright_blue(),
                fmt_env(browser).bright_white(),
                "netns".bright_blue(),
                fmt_env(netns).bright_white()
            );

            let self_rows = [
                ("mnt", self_ns.mnt.unique.to_string()),
                ("net", self_ns.net.unique.to_string()),
                ("pid", self_ns.pid.unique.to_string()),
            ];
            let self_kind_w = self_rows
                .iter()
                .map(|(k, _)| k.len())
                .max()
                .unwrap_or(4)
                .max("kind".len());
            let self_ns_w = self_rows
                .iter()
                .map(|(_, v)| v.len())
                .max()
                .unwrap_or(4)
                .max("self".len());

            println!();
            println!("{}", "self".bold().bright_magenta());
            let self_widths = [self_kind_w, self_ns_w];
            print_divider(&self_widths);
            println!(
                "| {:<kind_w$} | {:<ns_w$} |",
                "kind".bold(),
                "self".bold(),
                kind_w = self_kind_w,
                ns_w = self_ns_w
            );
            print_divider(&self_widths);
            for (kind, val) in &self_rows {
                println!(
                    "| {:<kind_w$} | {:<ns_w$} |",
                    kind,
                    val,
                    kind_w = self_kind_w,
                    ns_w = self_ns_w
                );
            }
            print_divider(&self_widths);

            if let Some(container_name) = container.as_deref().filter(|c| *c != "UNSPEC") {
                println!();
                println!(
                    "{} {}",
                    "claim".bold().bright_magenta(),
                    format!("profile={}", container_name).bright_white()
                );
                let registry = NamespacesRegistry::load_locked()?;
                let mut claim_rows: Vec<(String, String, String, bool, bool)> = Vec::new();
                if let Some(declared) = registry.profiles.get(container_name) {
                    for (label, declared_ns, self_actual) in [
                        ("mnt", &declared.mnt, &self_ns.mnt),
                        ("net", &declared.net, &self_ns.net),
                        ("pid", &declared.pid, &self_ns.pid),
                    ] {
                        claim_rows.push((
                            label.to_string(),
                            declared_ns.unique.to_string(),
                            self_actual.unique.to_string(),
                            declared_ns.unique == self_actual.unique,
                            false,
                        ));
                    }
                } else {
                    claim_rows.push((
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        false,
                        true,
                    ));
                }

                let claim_kind_w = claim_rows
                    .iter()
                    .map(|r| r.0.len())
                    .max()
                    .unwrap_or(4)
                    .max("kind".len());
                let claim_declared_w = claim_rows
                    .iter()
                    .map(|r| r.1.len())
                    .max()
                    .unwrap_or(8)
                    .max("declared".len());
                let claim_self_w = claim_rows
                    .iter()
                    .map(|r| r.2.len())
                    .max()
                    .unwrap_or(4)
                    .max("self".len());
                let claim_widths = [claim_kind_w, claim_declared_w, claim_self_w, status_width];

                print_divider(&claim_widths);
                println!(
                    "| {:<kind_w$} | {:<decl_w$} | {:<self_w$} | {:<status_w$} |",
                    "kind".bold(),
                    "declared".bold(),
                    "self".bold(),
                    "status".bold(),
                    kind_w = claim_kind_w,
                    decl_w = claim_declared_w,
                    self_w = claim_self_w,
                    status_w = status_width
                );
                print_divider(&claim_widths);
                for (kind, declared_val, self_val, ok, missing) in claim_rows {
                    let status_plain = if missing {
                        "MISSING"
                    } else if ok {
                        "OK"
                    } else {
                        "DIFF"
                    };
                    let status_padded = format!("{:<width$}", status_plain, width = status_width);
                    let status_colored = if missing {
                        format!("{}", status_padded.yellow().bold())
                    } else if ok {
                        format!("{}", status_padded.green().bold())
                    } else {
                        format!("{}", status_padded.red().bold())
                    };
                    println!(
                        "| {:<kind_w$} | {:<decl_w$} | {:<self_w$} | {} |",
                        kind,
                        declared_val,
                        self_val,
                        status_colored,
                        kind_w = claim_kind_w,
                        decl_w = claim_declared_w,
                        self_w = claim_self_w
                    );
                }
                print_divider(&claim_widths);
            }

            if let Some(proc) = target_ns {
                let target_pid = target_pid.expect("pid must exist when proc namespaces were built");
                println!();
                println!(
                    "{} {}",
                    "pid".bold().bright_magenta(),
                    format!("{} vs self", target_pid).bright_white()
                );
                let mut pid_rows: Vec<(String, String, String, bool)> = Vec::new();
                for (label, theirs, ours) in [
                    ("mnt", &proc.mnt, &self_ns.mnt),
                    ("net", &proc.net, &self_ns.net),
                    ("pid", &proc.pid, &self_ns.pid),
                ] {
                    pid_rows.push((
                        label.to_string(),
                        theirs.unique.to_string(),
                        ours.unique.to_string(),
                        theirs.unique == ours.unique,
                    ));
                }

                let pid_kind_w = pid_rows
                    .iter()
                    .map(|r| r.0.len())
                    .max()
                    .unwrap_or(4)
                    .max("kind".len());
                let pid_target_w = pid_rows
                    .iter()
                    .map(|r| r.1.len())
                    .max()
                    .unwrap_or(6)
                    .max("target".len());
                let pid_self_w = pid_rows
                    .iter()
                    .map(|r| r.2.len())
                    .max()
                    .unwrap_or(4)
                    .max("self".len());
                let pid_widths = [pid_kind_w, pid_target_w, pid_self_w, status_width];

                print_divider(&pid_widths);
                println!(
                    "| {:<kind_w$} | {:<target_w$} | {:<self_w$} | {:<status_w$} |",
                    "kind".bold(),
                    "target".bold(),
                    "self".bold(),
                    "status".bold(),
                    kind_w = pid_kind_w,
                    target_w = pid_target_w,
                    self_w = pid_self_w,
                    status_w = status_width
                );
                print_divider(&pid_widths);
                for (kind, target_val, self_val, ok) in pid_rows {
                    let status_plain = if ok { "OK" } else { "DIFF" };
                    let status_padded = format!("{:<width$}", status_plain, width = status_width);
                    let status_colored = if ok {
                        format!("{}", status_padded.green().bold())
                    } else {
                        format!("{}", status_padded.red().bold())
                    };
                    println!(
                        "| {:<kind_w$} | {:<target_w$} | {:<self_w$} | {} |",
                        kind,
                        target_val,
                        self_val,
                        status_colored,
                        kind_w = pid_kind_w,
                        target_w = pid_target_w,
                        self_w = pid_self_w
                    );
                }
                print_divider(&pid_widths);
            }

            let mount_ns = (std::fs::metadata("/proc/self/ns/mnt"), std::fs::metadata("/proc/1/ns/mnt"));
            println!();
            match mount_ns {
                (Ok(self_mnt), Ok(init_mnt)) => {
                    let isolated = self_mnt.dev() != init_mnt.dev() || self_mnt.ino() != init_mnt.ino();
                    println!(
                        "{} {} {}",
                        "mount_ns".bold().bright_blue(),
                        if isolated {
                            "isolated".green().bold().to_string()
                        } else {
                            "host-shared".red().bold().to_string()
                        },
                        format!("(self_ino={} init_ino={})", self_mnt.ino(), init_mnt.ino())
                            .bright_black(),
                    );
                }
                (Err(e), _) | (_, Err(e)) => {
                    println!(
                        "{} {} {}",
                        "mount_ns".bold().bright_blue(),
                        "unknown".yellow().bold(),
                        format!("({})", e).bright_black()
                    );
                }
            }
            println!();
        }
        /// We are just putting state in proc now, basically. Seems cleaner
        MainCommand::Enter { sargs, target } => {
            let mut shell_prefs = ShellPrefs::default();
            shell_prefs.take_args(sargs);
            shell_prefs.adjust();

            // Resolve the bind mount path: profile name resolves to /nsp3/{name}/net,
            // otherwise treat as an explicit path if it starts with /, ./, or ~/
            let (resolved_path, nsdata) = {
                let t = &target;
                if t.starts_with('/') || t.starts_with("./") || t.starts_with("~/") || t == "~" {
                    let vars = PathExpansionState::without_instance();
                    let p = vars.expand(Path::new(t));
                    (Some(p.clone()), state_paths::metadata_for_bind(&p))
                } else {
                    let p = state_paths::profile_netns_bind(t);
                    let m = state_paths::profile_ns_meta(t);
                    info!("Resolved profile name {:?} to {:?}", t, &p);
                    (Some(p), m)
                }
            };

            if let Some(path) = resolved_path {
                if let Some(ns_alive) = read_ns_alive_opt(&nsdata) {
                    enter_ns(&ns_alive, &path)?;
                    apply_ns_env(&mut shell_prefs, &ns_alive);
                } else {
                    error!("NS data not found at {:?}", nsdata)
                }
            } else {
                error!("specify --name <profile> or a path");
            }

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;

            rt.block_on(async {
                let rx = shell_prefs.spawn()?;
                rx.wait_for_child().await?;

                aok!()
            })?;
        }
        MainCommand::Install { dir: dstdir } => {
            if !dstdir.exists() {
                bail!(
                    "target directory {:?} does not exist. you have to create it manually",
                    &dstdir
                )
            }
            let dstdir_abs = dstdir.canonicalize()?;
            let selfprog = std::env::current_exe()?;
            let mut sproxyf = selfprog.clone();
            let overwrite = |src: &Path, path: &Path| {
                warn!("installing {:?} to {:?}", src, path);
                if path.exists() {
                    std::fs::remove_file(path)?;
                }
                std::fs::copy(src, path)?;
                aok!()
            };
            let selfprogdst = dstdir.join(selfprog.file_name().unwrap());
            overwrite(&selfprog, &selfprogdst)?;
            sproxyf.set_file_name("sproxy");

            let fd = dstdir.join(sproxyf.file_name().unwrap());
            overwrite(&sproxyf, &fd)?;
            let f = std::fs::File::open(&fd)?;
            let perms = Permissions::from_mode(0o6755);
            f.set_permissions(perms)?;
            let meta = f.metadata()?;
            warn!(
                "{fd:?}, uid={:?}, gid={}, suid={}",
                meta.uid(),
                meta.gid(),
                meta.permissions().mode() & 0o4000 != 0
            );
            let short_path = dstdir_abs.join("sp");
            let fd_abs = fd.canonicalize()?;
            warn!("Installing symlink {:?} -> {:?}", &short_path, &fd_abs);
            symlink(&fd_abs, &short_path);
            let short_path_unpriv = dstdir_abs.join("nsp");
            let selfprogdst_abs = selfprogdst.canonicalize()?;
            warn!(
                "Installing symlink {:?} -> {:?}",
                &short_path_unpriv, &selfprogdst_abs
            );
            symlink(&selfprogdst_abs, &short_path_unpriv);

            sproxyf.set_file_name("nswrap");
            let fd = dstdir.join(sproxyf.file_name().unwrap());
            overwrite(&sproxyf, &fd)?;
        }
        MainCommand::Completions { fish } => {
            if fish {
                if let Some(home) = std::env::var_os("HOME") {
                    let dir = PathBuf::from(home)
                        .join(".config")
                        .join("fish")
                        .join("completions");
                    std::fs::create_dir_all(&dir)?;

                    for bin_name in ["sp", "nsp", "nsproxy"] {
                        let mut cmd = Cli::command();
                        let mut buf = Vec::new();
                        generate(Fish, &mut cmd, bin_name, &mut buf);
                        let path = dir.join(format!("{}.fish", bin_name));
                        info!(
                            "Installing fish completion for '{}' at {:?}",
                            bin_name, path
                        );
                        std::fs::write(&path, &buf)?;
                    }
                } else {
                    warn!("HOME is not set; skipping fish completion install");
                }
            } else {
                warn!("No completion target specified; use --fish");
            }
        }
        MainCommand::Clean { veth } => {
            if veth {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;

                rt.block_on(async {
                    let cmd = tokio_netlink_conn()?;
                    info!("trying to remove v_out if it exists");
                    let default_v = cmd.fetch_link_by_name("v_out".to_owned()).await?;
                    cmd.link().del(default_v.header.index).execute().await?;
                    warn!("v_out removed");
                    aok!(())
                })?;
            }
        }
        MainCommand::Gen { save_to } => {
            let conf = HotConfig::default();
            let json = serde_json::to_string_pretty(&conf)?;

            std::fs::write(&save_to, json)?;
        }
        MainCommand::Netlink => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;

            rt.block_on(async {
                let nl = tokio_netlink_conn()?;
                let addrs = nl.fetch_all_ip_addrs().await?;
                for a in addrs {
                    println!("{}", a);
                }
                Ok::<(), anyhow::Error>(())
            })?;
        }
        MainCommand::Curl { url, proxy } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;

            rt.block_on(async {
                let client = if let Some(proxy_addr) = proxy {
                    let proxy_url = format!("socks5h://{}", proxy_addr);
                    info!("using proxy: {}", proxy_url);
                    reqwest::Client::builder()
                        .proxy(reqwest::Proxy::all(proxy_url)?)
                        .build()?
                } else {
                    reqwest::Client::builder()
                        .redirect(Policy::default())
                        .build()?
                };

                info!("requesting: {}", url);
                match client.get(url).send().await {
                    Ok(response) => {
                        println!("Status: {}", response.status());
                        match response.text().await {
                            Ok(body) => println!("{}", body),
                            Err(e) => warn!("failed to read response body: {}", e),
                        }
                    }
                    Err(e) => warn!("request failed: {:?}", e),
                }
                Ok::<(), anyhow::Error>(())
            })?;
        }
        MainCommand::Forward { src, dst } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;

            if dst == src {
                bail!("src==dst dead loop");
            }

            rt.block_on(async {
                let list = format!("0.0.0.0:{}", src);
                let listener = tokio::net::TcpListener::bind(&list).await?;
                info!("tcp forward listening on {}", &list);

                loop {
                    let (mut client, _) = listener.accept().await?;
                    let dst_addr = format!("127.0.0.1:{}", dst);

                    tokio::spawn(async move {
                        match tokio::net::TcpStream::connect(&dst_addr).await {
                            Ok(mut server) => {
                                info!("forwarded connection to {}", dst_addr);
                                if let Err(e) =
                                    tokio::io::copy_bidirectional(&mut client, &mut server).await
                                {
                                    warn!("forward error: {}", e);
                                }
                            }
                            Err(e) => {
                                warn!("failed to connect to {}: {}", dst_addr, e);
                            }
                        }
                    });
                }

                aok!()
            })?;
        }
        MainCommand::Template {
            path,
            name,
            reset,
            update,
        } => {
            if reset && update {
                bail!("Cannot use --reset and --update together");
            }

            info!("Profile Creation");
            info!("Creating profile instance with isolated state directory");
            info!("Each profile can only be instantiated once (e.g., for VS Code isolation)");
            info!("");

            // Derive name from config file stem if not provided
            let clean_name = if let Some(ref name) = name {
                // Sanitize provided name: extract filename, remove .json extension
                let name_path = PathBuf::from(name);
                name_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(name)
                    .to_string()
            } else {
                // Derive from config path
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| anyhow!("cannot derive profile name from path: {:?}", path))?
                    .to_string()
            };

            info!("Profile name: {}", clean_name);
            info!("Template config: {:?}", path);

            // Create target directory at /nsp3/{clean_name}
            let target_dir = state_paths::profile_dir(&clean_name);
            info!("Target directory: {:?}", target_dir);

            let profile_path = target_dir.join("profile.json");
            let hot_path = target_dir.join("hot.json");

            if update {
                // Update mode: check that profile exists
                if !profile_path.exists() {
                    bail!(
                        "profile does not exist at {:?}. Use without --update to create.",
                        profile_path
                    );
                }

                info!("Update mode - updating existing profile...");

                // Load the new template
                info!("Loading new template from {:?}...", path);
                let mut profile = TemplateConfig::load(&path)?;
                info!("Template loaded successfully");

                // Expand @ placeholders
                info!("Expanding @ placeholders to: {:?}", target_dir);
                profile.expand_placeholders(&target_dir);

                // Wellness checks
                info!("Running wellness checks...");

                // Check if mount sources exist
                let mut missing_sources = Vec::new();
                let mut existing_sources = Vec::new();
                for m in &profile.mounts {
                    if !m.source.exists() {
                        missing_sources.push(&m.source);
                    } else {
                        existing_sources.push(&m.source);
                    }
                }

                if !missing_sources.is_empty() {
                    warn!("Missing mount sources:");
                    for src in &missing_sources {
                        warn!("  ✗ {:?}", src);
                    }
                    bail!("Some mount sources do not exist. Create them manually or use --reset.");
                }

                info!("All mount sources available:");
                for src in &existing_sources {
                    info!("  ✓ {:?}", src);
                }

                // Check hot config
                if hot_path.exists() {
                    info!("✓ Hot config exists: {:?}", hot_path);
                } else {
                    warn!("Hot config does not exist at {:?}", hot_path);
                }

                // Check cwd if specified
                if let Some(ref cwd) = profile.sargs.cwd {
                    if cwd.exists() {
                        info!("✓ Working directory exists: {:?}", cwd);
                    } else {
                        warn!("Working directory does not exist: {:?}", cwd);
                    }
                }

                // Update profile config (overwrite profile.json, keep hot.json)
                info!("Updating profile configuration...");
                let mut new_profile = profile.clone();
                new_profile.hot = hot_path;

                let profile_json = serde_json::to_string_pretty(&new_profile)?;
                std::fs::write(&profile_path, profile_json)?;

                info!("");
                info!("✓ Profile updated successfully");
                info!("Config: {:?}", profile_path);
                info!("Hot config: {:?} (unchanged)", new_profile.hot);
                info!("");
                info!("Note: Existing directories and files were not modified");
            } else {
                // Create mode (original logic)

                // If reset flag is set, remove the entire directory first
                if reset && target_dir.exists() {
                    warn!("Reset flag enabled - removing existing profile directory");

                    // Remove namespace bind mount if it exists
                    let ns_bind = state_paths::profile_netns_bind(&clean_name);
                    if ns_bind.exists() {
                        warn!("Removing namespace bind mount at {:?}", &ns_bind);
                        if let Err(e) = rm_mount(&ns_bind) {
                            warn!("Failed to unmount {:?}: {:?}", &ns_bind, e);
                        }
                    }
                    // Remove sidecar metadata JSON
                    let ns_meta = state_paths::profile_ns_meta(&clean_name);
                    if ns_meta.exists() {
                        std::fs::remove_file(&ns_meta)?;
                    }

                    std::fs::remove_dir_all(&target_dir)?;
                    info!("Removed existing directory");
                }

                info!("Creating profile directory structure...");
                std::fs::create_dir_all(&target_dir)?;

                if profile_path.exists() && !reset {
                    bail!(
                        "profile config already exists: {:?}. Use --reset to recreate from scratch or --update to update config.",
                        profile_path
                    );
                }

                // Load the profile template from provided path
                info!("Loading profile template from {:?}...", path);
                let mut profile = TemplateConfig::load(&path)?;
                info!("Template loaded successfully");

                // Expand @ placeholders for directory creation
                info!("Expanding @ placeholders to: {:?}", target_dir);
                profile.expand_placeholders(&target_dir);

                // Create all referenced directories
                if let Some(ref cwd) = profile.sargs.cwd {
                    if !cwd.exists() {
                        info!("Creating working directory: {:?}", cwd);
                        std::fs::create_dir_all(cwd)?;
                        warn!("Created cwd: {:?}", cwd);
                    }
                }

                // Determine ownership for created directories
                info!("Determining ownership for created directories...");
                let (owner_uid, owner_gid) = if let Some(uid) = profile.sargs.uid {
                    let gid = profile.sargs.gid.unwrap_or_else(|| {
                        uzers::get_user_by_uid(uid)
                            .map(|u| u.primary_group_id())
                            .unwrap_or(uid)
                    });
                    (uid, gid)
                } else {
                    use nix::unistd::getresuid;
                    use nsproxy_common::UID_HINT_VAR;

                    let uid = if let Ok(id) = std::env::var(UID_HINT_VAR) {
                        id.parse()?
                    } else if let Ok(id) = std::env::var("SUDO_UID") {
                        id.parse()?
                    } else {
                        let res = getresuid()?;
                        if !res.real.is_root() {
                            res.real.as_raw()
                        } else {
                            1000 // fallback
                        }
                    };

                    let gid = uzers::get_user_by_uid(uid)
                        .map(|u| u.primary_group_id())
                        .unwrap_or(uid);
                    (uid, gid)
                };
                info!("Using ownership: uid={}, gid={}", owner_uid, owner_gid);

                info!("Creating mount source directories...");
                for m in &profile.mounts {
                    if !m.source.exists() {
                        info!("  Creating: {:?}", m.source);
                        std::fs::create_dir_all(&m.source)?;
                        // Set ownership
                        nix::unistd::chown(
                            &m.source,
                            Some(nix::unistd::Uid::from_raw(owner_uid)),
                            Some(nix::unistd::Gid::from_raw(owner_gid)),
                        )?;
                        info!("  Set ownership to uid={}, gid={}", owner_uid, owner_gid);
                    } else {
                        info!("  Mount source exists: {:?}", m.source);
                    }
                }

                // Copy hot config if it exists, otherwise create from hot_init or default
                info!("Setting up hot config...");
                if profile.hot.exists() && profile.hot != hot_path {
                    info!("Copying hot config from {:?}", profile.hot);
                    std::fs::copy(&profile.hot, &hot_path)?;
                    warn!("Copied hot config: {:?} -> {:?}", profile.hot, hot_path);
                } else if !hot_path.exists() {
                    info!("Creating hot config from profile.hot_init");
                    let hot = profile.hot_init.clone().unwrap_or_default();
                    hot.save(&hot_path)?;
                    warn!("Created hot config: {:?}", hot_path);
                }

                // Update profile to point to new hot config location
                info!("Writing profile configuration...");
                let mut new_profile = profile.clone();
                new_profile.hot = hot_path;

                let profile_json = serde_json::to_string_pretty(&new_profile)?;
                std::fs::write(&profile_path, profile_json)?;

                info!("");
                info!("✓ Profile created successfully");
                info!("Location: {:?}", target_dir);
                info!("Config: {:?}", profile_path);
                info!("Hot config: {:?}", new_profile.hot);
            }
        }
        MainCommand::Up {
            profile,
            cmd,
            simulate_protocol_no_upgrade,
            simulate_conn_close,
            simulate_slow_shutdown,
        } => {
            // Show build identity and human-readable build time early for diagnostics.
            let build_hash = nsproxy_core::build_tree_hash();
            let build_epoch = nsproxy_core::build_epoch_secs();
            let human_time = chrono::NaiveDateTime::from_timestamp_opt(build_epoch as i64, 0)
                .map(|dt: chrono::NaiveDateTime| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "unknown".to_string());
            warn!(
                profile = profile.as_str(),
                "sp up starting: build_hash={} build_time={} (epoch={})",
                build_hash,
                human_time,
                build_epoch
            );
            let profile_path = state_paths::profile_config(&profile);
            if !profile_path.exists() {
                bail!(
                    "profile config does not exist: {:?}. Use 'profile' subcommand to create it.",
                    profile_path
                );
            }
            let profile_conf = TemplateConfig::load(&profile_path)?;

            // If a CLI-specified daemon request was provided, translate and
            // send it to the already-running `up` daemon for this profile.
            if let Some(cli_req) = cmd {
                // Translate CLI request into `diag::DaemonRequest`.
                let req = match cli_req {
                    CliDaemonRequest::GetProcessList => diag::DaemonRequest::GetProcessList,
                    CliDaemonRequest::Ping => diag::DaemonRequest::Ping,
                    CliDaemonRequest::Kill { pid } => diag::DaemonRequest::Kill { pid },
                    CliDaemonRequest::Stop => diag::DaemonRequest::Stop,
                    CliDaemonRequest::Spawn { args } => {
                        let dra = diag::SpawnArgs {
                            uid: args.uid,
                            gid: args.gid,
                            exec: args.exec,
                            cwd: args.cwd,
                            gids: args.gids,
                            args: args.args,
                            ns: args.ns,
                        };
                        diag::DaemonRequest::Spawn { args: dra }
                    }
                    CliDaemonRequest::SpawnCli { cli_json, ns } => {
                        // Parse provided JSON into `Cli` and bincode-serialize it.
                        let cli_struct: Cli = serde_json::from_str(&cli_json)
                            .map_err(|e| anyhow!("failed to parse cli JSON: {}", e))?;
                        let b = bincode::serialize(&cli_struct)?;
                        diag::DaemonRequest::SpawnCli { cli_bincode: b, ns }
                    }
                };

                // Send over the profile's up.sock and print a single response if any.
                let sock_path = diag::up_sock_path(&profile);
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                rt.block_on(async {
                    let mut stream = diag::connect_up_daemon(&sock_path).await?;
                    stream.send_unstable_request(&req).await?;
                    if let Some(evt) = stream.next_event().await? {
                        println!("{:?}", evt);
                    }
                    Ok::<(), anyhow::Error>(())
                })?;
                return Ok(());
            }

            let bind_mount = state_paths::profile_netns_bind(&profile);
            if let Some(parent) = bind_mount.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let ns_meta = state_paths::profile_ns_meta(&profile);
            let mut upkeeper_pid: Option<u32> = None;
            let mut existing_up_daemon_pid: Option<u32> = None;
            if ns_meta.exists() {
                info!("Reading NS metadata from {:?}", &ns_meta);
                warn!(
                    profile = profile.as_str(),
                    ns_meta = %ns_meta.display(),
                    "up preflight: ns metadata present; evaluating existing daemon state"
                );
                if let Some(ns_alive) = read_ns_alive_opt(&ns_meta) {
                    warn!(
                        profile = profile.as_str(),
                        up_pid = ?ns_alive.up_pid,
                        child_pid = ?ns_alive.child_pid,
                        "up preflight: loaded NsAlive metadata"
                    );
                    let alive_child = ns_alive.child_pid.filter(|pid| pid_is_alive(*pid));

                    warn!(
                        profile = profile.as_str(),
                        alive_child = ?alive_child,
                        "up preflight: probed live child pid"
                    );

                    if let Some(target_pid) = alive_child {
                        upkeeper_pid = Some(target_pid);
                        existing_up_daemon_pid = ns_alive.up_pid.filter(|pid| pid_is_alive(*pid));
                        warn!(
                            profile = profile.as_str(),
                            target_pid,
                            "up preflight: existing namespace detected; will use clone3 no-newns replacement path"
                        );
                    }
                }
            }

            let clone = if upkeeper_pid.is_some() {
                warn!(
                    profile = profile.as_str(),
                    target_pid = ?upkeeper_pid,
                    "up startup: using clone3 without new namespaces; child will enter existing namespaces"
                );
                nsproxy_core::sys::clone3::<false>(false, false)
            } else {
                // Fresh profile start: create new mount/net namespaces.
                nsproxy_core::sys::clone3::<true>(true, true)
            };
            match clone {
                Ok(clone) => match clone {
                    Clone3Result::IsChild { mut tx } => {
                        if let Some(target_pid) = upkeeper_pid {
                            warn!(
                                profile = profile.as_str(),
                                target_pid,
                                "up child: entering existing namespaces"
                            );
                            enter_all_profile_namespaces_of_pid(target_pid)?;
                        }

                        // Signal to parent that child namespace context is ready to inspect.
                        tx.write(&[1])?;

                        let mut buf = [0; 1];
                        enable_ping_all()?;
                        tx.read(&mut buf)?; // wait for bind mount

                        if upkeeper_pid.is_none() {
                            // always done when there is new mount namespace
                            mount_bind_root()?;
                            // mounting DNS related things is also basic to either overlay or pivot sandbox
                            mount_resolv_conf("100.68.0.2")?;
                            mount_nsswitch_conf()?;
                        } else {
                            warn!(
                                profile = profile.as_str(),
                                "up child: reusing existing namespace mounts; skip fresh namespace bootstrap mounts"
                            );
                        }

                        loop {
                            std::thread::park();
                        }
                    }
                    Clone3Result::Parent {
                        child_pid, mut tx, ..
                    } => {
                        let mut ready = [0; 1];
                        tx.read(&mut ready)?;

                        let parent_mnt = ExactNS::from_source((PidPath::Selfproc, "mnt"))?;
                        let parent_net = ExactNS::from_source((PidPath::Selfproc, "net"))?;
                        let parent_pid = ExactNS::from_source((PidPath::Selfproc, "pid"))?;
                        let child_mnt = ExactNS::from_source((PidPath::N(child_pid), "mnt"))?;
                        let child_net = ExactNS::from_source((PidPath::N(child_pid), "net"))?;
                        let child_pid_ns = ExactNS::from_source((PidPath::N(child_pid), "pid"))?;
                        info!(
                            "ns indicator parent[mnt={},net={},pid={}] child[mnt={},net={},pid={}]",
                            parent_mnt.unique,
                            parent_net.unique,
                            parent_pid.unique,
                            child_mnt.unique,
                            child_net.unique,
                            child_pid_ns.unique,
                        );

                        if let Some(parent) = bind_mount.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        let path = format!("/proc/{}/ns/net", child_pid);
                        let path = PathBuf::from(path);
                        mount_ns(&path, &bind_mount)?;
                        let bind_net = ExactNS::from_source(bind_mount.clone())?;
                        info!(
                            "up ns indicator bind_mount[mnt_path={:?},net={}]",
                            bind_mount,
                            bind_net.unique
                        );

                        NamespacesRegistry::update_locked(|registry| {
                            registry.profiles.insert(
                                profile.clone(),
                                ProfileNamespaces {
                                    mnt: child_mnt.clone(),
                                    net: child_net.clone(),
                                    pid: child_pid_ns.clone(),
                                },
                            );
                            Ok(())
                        })?;

                        info!("Updating NS metadata at {:?}", &ns_meta);
                        let up_pid = std::process::id();
                        update_ns_alive(&ns_meta, |ns_alive| {
                            ns_alive.profile_name = Some(profile.clone());
                            ns_alive.browser_profile = profile_conf.browser_profile.clone();
                            ns_alive.bind_mount = bind_mount.clone();
                            ns_alive.child_pid = Some(child_pid as u32);
                            ns_alive.up_pid = Some(up_pid);
                        })?;
                        warn!("Auxiliary data written to {:?}", &ns_meta);

                        if let Some(old_up_pid) = existing_up_daemon_pid.filter(|pid| pid_is_alive(*pid)) {
                            warn!(
                                profile = profile.as_str(),
                                old_up_pid,
                                "up replacement: new child keeper is ready; requesting graceful shutdown of old up daemon"
                            );
                            let sock_path = diag::up_sock_path(&profile);
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()?;
                            rt.block_on(async {
                                let mut stream = diag::connect_up_daemon_stable(&sock_path).await?;
                                stream.send_stable_request(&diag::StableRequest::GracefulShutdown).await?;
                                match tokio::time::timeout(Duration::from_secs(5), stream.next_event()).await {
                                    Ok(Ok(Some(diag::UpWireEvent::Stable(diag::StableEvent::ShuttingDown))))
                                    | Ok(Ok(Some(diag::UpWireEvent::Unstable(diag::DaemonEvent::Stopping))))
                                    | Ok(Ok(None)) => Ok::<(), anyhow::Error>(()),
                                    Ok(Ok(Some(diag::UpWireEvent::Stable(diag::StableEvent::Error { msg })))) => {
                                        bail!("old up daemon returned error on graceful shutdown: {}", msg)
                                    }
                                    Ok(Ok(Some(diag::UpWireEvent::Unstable(diag::DaemonEvent::Error { msg })))) => {
                                        bail!("old up daemon returned error on graceful shutdown: {}", msg)
                                    }
                                    Ok(Ok(Some(other))) => {
                                        bail!("unexpected response from old up daemon: {:?}", other)
                                    }
                                    Ok(Err(e)) => Err(e.into()),
                                    Err(_) => bail!(
                                        "timed out waiting for graceful-shutdown acknowledgement from old up daemon"
                                    ),
                                }
                            })?;
                            warn!(
                                profile = profile.as_str(),
                                old_up_pid,
                                "up replacement: old up daemon shutdown acknowledged"
                            );
                        }

                        tx.write(&[0])?;

                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;
                        rt.block_on(run_up_daemon(
                            &profile,
                            ns_meta,
                            child_pid as u32,
                            cli.control_socket.clone(),
                            simulate_protocol_no_upgrade,
                            simulate_conn_close,
                            simulate_slow_shutdown,
                        ))?;
                        std::process::exit(0);
                    }
                },
                Err(er) => report_clone3_err(&er)?,
            }
        }
        MainCommand::Down { profile } => {
            let ns_meta = state_paths::profile_ns_meta(&profile);
            let bind_mount = state_paths::profile_netns_bind(&profile);

            // Kill the keeper process if we know its PID.
            if ns_meta.exists() {
                if let Ok(content) = std::fs::read_to_string(&ns_meta) {
                    if let Ok(ns_alive) = serde_json::from_str::<nsproxy_core::NsAlive>(&content) {
                        if let Some(pid) = ns_alive.child_pid {
                            let proc_path = PathBuf::from("/proc").join(pid.to_string());
                        if proc_path.exists() {
                            warn!("killing keeper process pid={}", pid);
                            if !kill_and_wait_for_exit(pid, Duration::from_secs(5)) {
                                warn!("keeper pid {} did not exit within 5 seconds", pid);
                            }
                        } else {
                            info!("keeper process pid={} is already gone", pid);
                        }
                        }
                    }
                }
                std::fs::remove_file(&ns_meta)?;
                info!("removed NS metadata {:?}", ns_meta);
            } else {
                warn!("no NS metadata found at {:?}", ns_meta);
            }

            NamespacesRegistry::update_locked(|registry| {
                registry.profiles.remove(&profile);
                Ok(())
            })?;

            // Unmount and remove the bind-mount file.
            if bind_mount.exists() {
                if let Err(e) = rm_mount(&bind_mount) {
                    warn!("failed to remove bind mount {:?}: {:?}", bind_mount, e);
                } else {
                    info!("removed bind mount {:?}", bind_mount);
                }
            } else {
                warn!(
                    "bind mount {:?} does not exist, nothing to unmount",
                    bind_mount
                );
            }

            warn!("profile '{}' is down", profile);
        }
        MainCommand::Serve {
            profile,
            tun_name,
            simple,
            no_default,
            log,
            clash,
            no_dns_capture,
        } => cmd_serve(
            profile,
            tun_name,
            simple,
            no_default,
            log,
            clash,
            no_dns_capture,
            cli.control_socket.clone(),
            &mut |level| {
                reload_handle.modify(|k| *k.filter_mut() = level)?;
                Ok(())
            },
        )?,
        MainCommand::Veth {
            profile,
            veth_name,
            log,
        } => {
            let ns_meta = state_paths::profile_ns_meta(&profile);
            let ns_alive = read_ns_alive(&ns_meta)?;

            let child_pid = ns_alive
                .child_pid
                .ok_or_else(|| anyhow!("ns_alive has no child_pid"))?;

            let vname = veth_name.unwrap_or_else(|| profile.clone());
            let v_in = format!("{vname}_in");
            let v_out = format!("{vname}_out");
            let veth_net: Ipv4Network = "100.64.0.0/10".parse()?;
            let host_bits = 2;
            let subnet_prefix = 32 - host_bits;

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            if let Some(log) = log {
                reload_handle.modify(|k| *k.filter_mut() = log)?;
            }

            rt.block_on(async move {
                use tokio::io::AsyncWriteExt;

                let nl = tokio_netlink_conn()?;
                info!("attempting to add veths named, {}, {}", &v_out, &v_in);
                let addrs = nl.fetch_all_ip_addrs().await?;
                let ips: Vec<_> = addrs
                    .iter()
                    .filter_map(|f| match f {
                        IpNetwork::V4(v4) => Some(v4.ip()),
                        _ => None,
                    })
                    .collect();

                let v1: Option<Ipv4Addr> = find_vacant_ipv4_subnet(ips, veth_net, host_bits);
                if let Some(subnet) = v1 {
                    nl.add_veth(&v_out, &v_in).await;
                    let vin = nl.fetch_link_by_name(v_in.clone()).await?;
                    let msg: LinkMessageBuilder<LinkVeth> = LinkMessageBuilder::default()
                        .index(vin.header.index)
                        .setns_by_pid(child_pid as u32);
                    nl.link().set(msg.build()).execute().await;

                    let vout = nl.fetch_link_by_name(v_out.clone()).await?;
                    nl.address()
                        .add(
                            vout.header.index,
                            veth_addr_for(subnet, host_bits, true).into(),
                            subnet_prefix,
                        )
                        .execute()
                        .await?;
                    nl.link()
                        .set(
                            LinkMessageBuilder::<LinkUnspec>::default()
                                .index(vout.header.index)
                                .up()
                                .build(),
                        )
                        .execute()
                        .await?;

                    let clone = nsproxy_core::sys::clone3::<false>(false, false);
                    match clone {
                        Ok(clone) => match clone {
                            Clone3Result::IsChild { mut tx } => {
                                let ns_source = NSSource::Pid(child_pid as i32);
                                ns_source.enter(CloneFlags::CLONE_NEWNET)?;

                                let mut buf = [0u8; 4];
                                tx.read_exact(&mut buf)?;
                                let ip =
                                    veth_addr_for(Ipv4Addr::from_octets(buf), host_bits, false);

                                let rt = tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .build()?;
                                rt.block_on(async {
                                    let nl = tokio_netlink_conn()?;
                                    nl.up_lo().await?;
                                    let dev = nl.fetch_link_by_name(v_in).await?;
                                    nl.address()
                                        .add(dev.header.index, ip.into(), subnet_prefix)
                                        .execute()
                                        .await?;
                                    nl.link()
                                        .set(
                                            LinkMessageBuilder::<LinkUnspec>::default()
                                                .index(dev.header.index)
                                                .up()
                                                .build(),
                                        )
                                        .execute()
                                        .await?;
                                    Ok::<(), anyhow::Error>(())
                                })?;
                            }
                            Clone3Result::Parent { mut tx, .. } => {
                                tx.write(subnet.as_octets())?;
                            }
                        },
                        Err(er) => warn!("Clone3 failed with {:?}", &er),
                    }
                } else {
                    tracing::error!("cannot find any vacant ip");
                }

                aok!()
            })?;
        }
        MainCommand::Basis { cmd } => match cmd {
            BasisCommand::Mount {} => {
                let source = PathBuf::from("/proc/self/ns/net");
                let bind_mount = state_paths::profile_netns_bind("basis");
                if let Some(parent) = bind_mount.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                mount_ns(&source, &bind_mount)?;
                info!("Basis netns mounted at {:?}", bind_mount);
            }
            BasisCommand::Enter { sargs } => {
                let mut shell_prefs = ShellPrefs::default();
                shell_prefs.take_args(sargs);
                shell_prefs.adjust();

                let bind_mount = state_paths::profile_netns_bind("basis");
                let nsdata = state_paths::profile_ns_meta("basis");

                if let Some(ns_alive) = read_ns_alive_opt(&nsdata) {
                    enter_ns(&ns_alive, &bind_mount)?;
                    apply_ns_env(&mut shell_prefs, &ns_alive);
                } else {
                    let ns = NSSource::Path(bind_mount.clone());
                    ns.enter(CloneFlags::CLONE_NEWNET)?;
                    shell_prefs.set_ns_env(Some(&bind_mount.to_string_lossy()));
                }

                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;

                rt.block_on(async {
                    let rx = shell_prefs.spawn()?;
                    rx.wait_for_child().await?;

                    aok!()
                })?;
            }
        },
        MainCommand::StateTree => {
            let tree = nsproxy_core::state_blueprint::global_state_tree();
            println!("{}", tree.render_tree());
        },
        MainCommand::Version => {
            println!("hash={}", nsproxy_core::build_tree_hash());
            println!("epoch={}", nsproxy_core::build_epoch_secs());
        },
        MainCommand::Uplink { kind } => cmd_uplink(kind)?,
        MainCommand::Sandbox { profile, sargs } => {
            // Pivot-root sandbox: enter an existing namespace, apply
            // TemplateConfig pivot, then watch HotConfig for mount changes.
            check_capsys()?;

            let profile_path = state_paths::profile_config(&profile);
            if !profile_path.exists() {
                bail!(
                    "profile config does not exist: {:?}. Use 'profile' subcommand to create it.",
                    profile_path
                );
            }
            let mut profile_conf = TemplateConfig::load(&profile_path)?;
            let instance_root = state_paths::profile_dir(&profile);
            profile_conf.expand_placeholders(&instance_root);

            let ns_meta = state_paths::profile_ns_meta(&profile);
            let ns_alive = read_ns_alive(&ns_meta)?;
            let bind_mount = state_paths::profile_netns_bind(&profile);

            // Enter the existing mount namespace.
            enter_ns(&ns_alive, &bind_mount)?;

            // Rigorous safety check: refuse to proceed if we're still in
            // the host mount namespace. This prevents corrupting the host.
            nsproxy_core::sandbox::assert_mount_ns_isolated()?;

            // Check if a previous sandbox is already in place (restart case).
            let sandbox_state = nsproxy_core::sandbox::detect_sandbox_state()?;

            // Determine before consuming sandbox_state whether a pivot root will be/was applied.
            // Hot mounts applied after a pivot must resolve source paths through /pivot (the old root).
            let is_pivot_mode = profile_conf.sandbox_mode == SandboxMode::Pivot;

            match sandbox_state {
                nsproxy_core::sandbox::SandboxState::AlreadyPivoted => {
                    info!("sandbox already applied, skipping pivot");
                }
                nsproxy_core::sandbox::SandboxState::Virgin => {
                    if is_pivot_mode {
                        // Build and pivot into the sandbox root.
                        nsproxy_core::sandbox::apply_pivot(&profile_conf, &profile)?;
                    }
                }
            }

            // Resolve the hot config path (already expanded).
            let hot_path = profile_conf.hot.clone();

            // After a pivot the process root is the new tmpfs root; the old host
            // filesystem is accessible at /pivot.  Source paths in hot mounts are
            // host paths, so we must chroot them to /pivot when in pivot mode.
            let hot_vars = {
                let base = nsproxy_core::PathExpansionState::for_instance(&instance_root);
                if is_pivot_mode {
                    base.with_src_chroot(std::path::Path::new("/pivot"))
                } else {
                    base
                }
            };
            if hot_path.exists() {
                let fc = std::fs::read_to_string(&hot_path)?;
                if let Ok(mut hot) = serde_json::from_str::<HotConfig>(&fc) {
                    hot.expand_with(&hot_vars);
                    if let Ok(mounts) = hot.merged_mounts() {
                        if !mounts.is_empty() {
                            nsproxy_core::sandbox::apply_mounts(&hot_vars, &mounts)?;
                        }
                    }
                }
            }

            let mut shell_prefs = ShellPrefs::default();
            shell_prefs.take_args(sargs);
            if profile_conf.sargs.shell.is_some() {
                shell_prefs.take_args(profile_conf.sargs.clone());
            }
            apply_ns_env(&mut shell_prefs, &ns_alive);
            shell_prefs.adjust()?;

            // Spawn shell and watch hot config for mount changes.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let child = shell_prefs.spawn()?;

                // Watch hot config for changes in a background task.
                let hot_watch_path = hot_path.clone();
                let hot_watch_vars = hot_vars.clone();
                tokio::spawn(async move {
                    if let Err(e) = watch_hot_mounts(&hot_watch_path, hot_watch_vars).await {
                        warn!("hot config watcher exited: {}", e);
                    }
                });

                child.wait_for_child().await?;
                aok!()
            })?;
        }
        _ => unimplemented!(),
    }

    Ok(())
}

fn cmd_serve(
    profile: String,
    tun_name: Option<String>,
    simple: Option<nsproxy_common::routing::ProxyNym>,
    no_default: bool,
    log: Option<LevelFilter>,
    _clash: Option<String>,
    no_dns_capture: bool,
    control_socket: Option<PathBuf>,
    set_log: &mut dyn FnMut(LevelFilter) -> Result<()>,
) -> Result<()> {
    let ns_meta = state_paths::profile_ns_meta(&profile);
    let ns_alive = read_ns_alive(&ns_meta)?;

    let child_pid = ns_alive
        .child_pid
        .ok_or_else(|| anyhow!("ns_alive has no child_pid"))?;

    let hot_conf = state_paths::hot_config(&profile);
    if !hot_conf.exists() {
        bail!("hot config does not exist: {:?}", hot_conf);
    }

    let diag_path = diag::diag_sock_path(&profile);
    if diag_path.exists() {
        match std::os::unix::net::UnixStream::connect(&diag_path) {
            Ok(_) => {
                bail!(
                    "tun appears to be running (diag socket accepts connections): {:?}",
                    diag_path
                );
            }
            Err(e) => {
                warn!(
                    "diag socket probe failed ({}), proceeding with startup: {:?}",
                    e, diag_path
                );
            }
        }
    }
    let mtu = 1500;
    let tun_name = tun_name.unwrap_or_else(|| "tun2".to_owned());

    let clone = nsproxy_core::sys::clone3::<false>(false, false);
    match clone {
        Ok(clone) => match clone {
            Clone3Result::IsChild { mut tx } => {
                let hot_conf = hot_conf.clone();
                let ns_source = NSSource::Pid(child_pid as i32);
                ns_source.enter(CloneFlags::CLONE_NEWNS)?;
                ns_source.enter(CloneFlags::CLONE_NEWNET)?;

                let mut tun = TunMaker::default();
                tun.name = tun_name.clone();
                tun.mtu = mtu;
                let mut tun_state = tun.make()?;
                tun_state.sync_basic()?;
                let dev = Arc::into_inner(tun_state.fd.unwrap()).unwrap();
                let raw = dev.as_raw_fd();

                info!("send TUN fd");
                tx.send_fd(raw)?;
                drop(dev);

                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                rt.block_on(async {
                    use tokio::io::AsyncReadExt;
                    use tokio_send_fd::SendFd;
                    tx.set_nonblocking(true)?;
                    let mut tx = tokio::net::UnixStream::from_std(tx)?;

                    let nl = tokio_netlink_conn()?;
                    nl.up_lo().await?;

                    let txqueuelen = 500_000u32;
                    warn!(
                        "setting TUN txqueuelen to {} for high throughput",
                        txqueuelen
                    );
                    nl.link()
                        .set(
                            LinkMessageBuilder::<LinkUnspec>::default()
                                .index(tun_state.dev_index)
                                .append_extra_attribute(LinkAttribute::TxQueueLen(txqueuelen))
                                .build(),
                        )
                        .execute()
                        .await?;

                    if !no_default {
                        warn!("adding TUN as default route");
                        nl.ip_add_default_route(tun_state.dev_index).await?;
                    }

                    tokio::spawn(async move {
                        let conf = Some(hot_conf);
                        if let Some(conf) = conf {
                            let mut mnt: HashMap<PathBuf, PathBuf> = Default::default();
                            let mut read = [0u8; 24];
                            loop {
                                info!("in-ns wait for config");
                                let k = tx.read(&mut read[..]).await?;
                                if k < 1 {
                                    error!("in-ns config watcher exits due to EOF");
                                    break;
                                }
                                info!("in-ns reload config");
                                let fc = tokio::fs::read_to_string(&conf).await?;
                                match serde_json::from_str::<HotConfig>(&fc) {
                                    Ok(newconf) => {
                                        tx.write(&[0, 0, 0, 0]).await?;
                                        for (in_port, _dst) in &newconf.locals {
                                            let bind = std::net::TcpListener::bind(format!(
                                                "127.0.0.1:{}",
                                                in_port
                                            ))?;
                                            let raw = bind.as_raw_fd();
                                            tx.write(&in_port.to_le_bytes()).await?;
                                            tx.send_fd(raw).await?;
                                        }
                                        tx.write(&[0, 0, 0, 0]).await?;

                                        let _ = sync_links(None, &newconf).await;
                                    }
                                    _ => {}
                                }
                            }
                        }

                        aok!()
                    });

                    std::future::pending::<()>().await;
                    aok!()
                })?;
            }
            Clone3Result::Parent {
                child_pid,
                child_pidfd,
                mut tx,
            } => {
                let hot_conf = hot_conf.clone();
                info!("recved fd");
                let dev = tx.recv_fd()?;
                let dev = Arc::new(unsafe { AsyncDevice::from_fd(dev) }?);

                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?;
                if let Some(log) = log {
                    set_log(log)?;
                }

                // Record this process's PID as the serve process
                let serve_pid = std::process::id();
                update_ns_alive(&ns_meta, |ns_alive| {
                    ns_alive.serve_pid = Some(serve_pid);
                })?;
                info!("recorded serve_pid={} to {:?}", serve_pid, &ns_meta);

                rt.spawn(async move {
                    let fd = unsafe { PidFd::from_raw_fd(child_pidfd) };
                    let _ = fd.into_future().await?;
                    warn!("tun helper exited");
                    aok!()
                });

                rt.block_on(async move {
                    use tokio::io::AsyncWriteExt;

                    tx.set_nonblocking(true)?;
                    let mut tx = tokio::net::UnixStream::from_std(tx)?;

                    let (mut vdns_sx, vdns_rx) = mpsc::channel(1);
                    let (st_sx, acceptor) = flume::unbounded();
                    let (hot_reload_tx, hot_reload_rx) = tokio::sync::mpsc::channel(8);

                    let initial_hot = match tokio::fs::read_to_string(&hot_conf).await {
                        Ok(fc) => match serde_json::from_str::<HotConfig>(&fc) {
                            Ok(conf) => conf,
                            Err(e) => {
                                warn!(
                                    "failed to parse hot config {:?} at startup: {}, using default",
                                    hot_conf, e
                                );
                                HotConfig::default()
                            }
                        },
                        Err(e) => {
                            warn!(
                                "failed to read hot config {:?} at startup: {}, using default",
                                hot_conf, e
                            );
                            HotConfig::default()
                        }
                    };
                    let initial_hot = if no_dns_capture {
                        let mut h = initial_hot;
                        h.disable_dns_capture();
                        h.save(&hot_conf)?;
                        h
                    } else {
                        initial_hot
                    };

                    let (hot_tx, hot_rx) = tokio::sync::watch::channel(initial_hot.clone());
                    let shared_hot = Arc::new(hot_rx);

                    let hub = load_saved_uplink_hub()?;
                    let router_conf = nsproxy_core::uplink::router::RouterConfig {
                        mtu,
                        packet_info: false,
                        udp_timeout: Duration::from_secs(20),
                        diag_sock: Some(diag_path.clone()),
                    };
                    let mut router = nsproxy_core::uplink::router::Router::new(
                        dev,
                        router_conf,
                        hub,
                        Some(st_sx),
                        shared_hot,
                    )?;

                    let mut selected_proxy: Option<nsproxy_common::routing::ProxyID> = None;

                    if let Some(nym) = simple {
                        let proxy_id = {
                            let uplink = router.uplink().await;
                            uplink.nym_map.get(&nym).cloned().ok_or_else(|| {
                                anyhow!("Simple route proxy not found for nym {}", nym)
                            })?
                        };

                        router
                            .set_routing(nsproxy_core::uplink::simple_routing(proxy_id.clone()))
                            .await;
                        selected_proxy = Some(proxy_id);
                    }

                    router.init_diag(&diag_path).await?;

                    // If the UI passed a control socket, connect to it now (after the diag
                    // server is ready) and register the reversed connection as a diag client.
                    if let Some(ref ctrl_path) = control_socket {
                        match connect_and_greet_serve(ctrl_path, &profile).await {
                            Ok(stream) => {
                                info!("sp serve: connected to UI control socket as reversed diag client");
                                router.diag_handle().add_reversed_client(stream);
                            }
                            Err(e) => warn!("sp serve: failed to connect to control socket {:?}: {}", ctrl_path, e),
                        }
                    }

                    // Forward tracing logs to this profile's diag socket for the lifetime
                    // of this serve task and all explicitly-scoped spawned children.
                    let diag_srv_scope = router.diag_handle();
                    // Also register as the process-global sink so that tasks spawned without
                    // an explicit scope (e.g. router-internal tokio::spawn) forward logs here.
                    diag_srv_scope.install_as_global();
                    let scope_for_cmd = diag_srv_scope.clone();
                    let scope_for_watch = diag_srv_scope.clone();
                    diag_srv_scope.scope(async move {

                    // Drive the control-command loop emitted by diag clients.
                    if let Some(mut cmd_rx) = router.take_cmd_rx() {
                        let uplink_cmd = router.uplink.clone();
                        let hot_conf_cmd = hot_conf.clone();
                        let hot_tx = hot_tx.clone();
                        let reload_tx = hot_reload_tx.clone();
                        let diag_srv = router.diag_handle();
                        let dns_handle = router.dns_handle();
                        let mut selected_proxy = selected_proxy.clone();
                        tokio::spawn(scope_for_cmd.scope(async move {
                            while let Some(cmd) = cmd_rx.recv().await {
                                match cmd {
                                    diag::ControlCommand::ReloadUplink => {
                                        if let Ok(hub) = nsproxy_core::cmd_uplink::load_saved_uplink_hub() {
                                            let mut u = uplink_cmd.write().await;
                                            *u = hub;
                                            info!("uplink reloaded via diag cmd");
                                        }
                                    }
                                    diag::ControlCommand::ReloadHotConfig => {
                                        let _ = reload_tx.send(nsproxy_core::hot_reload::HotReloadTrigger::DirectReload).await;
                                        match tokio::fs::read_to_string(&hot_conf_cmd).await {
                                            Ok(fc) => match serde_json::from_str::<HotConfig>(&fc) {
                                                Ok(cfg) => {
                                                    let _ = hot_tx.send(cfg);
                                                    diag_srv.emit(diag::DiagEvent::HotConfigReloaded {
                                                        ts: diag::Timestamp::now(),
                                                        ok: true,
                                                        changed: true,
                                                        source: "direct".to_string(),
                                                        error: None,
                                                    });
                                                    info!("hot config reloaded");
                                                }
                                                Err(e) => {
                                                    diag_srv.emit(diag::DiagEvent::HotConfigReloaded {
                                                        ts: diag::Timestamp::now(),
                                                        ok: false,
                                                        changed: false,
                                                        source: "direct".to_string(),
                                                        error: Some(e.to_string()),
                                                    });
                                                    warn!("hot config parse error: {e}");
                                                }
                                            },
                                            Err(e) => {
                                                diag_srv.emit(diag::DiagEvent::HotConfigReloaded {
                                                    ts: diag::Timestamp::now(),
                                                    ok: false,
                                                    changed: false,
                                                    source: "direct".to_string(),
                                                    error: Some(e.to_string()),
                                                });
                                                warn!("hot config read error: {e}");
                                            }
                                        }
                                    }
                                    diag::ControlCommand::SetSimpleRouting { proxy_id } => {
                                        let fn_ = nsproxy_core::uplink::simple_routing(proxy_id.clone());
                                        uplink_cmd.write().await.set_routing(fn_);
                                        selected_proxy = Some(proxy_id);
                                        diag_srv.emit(diag::DiagEvent::RoutingState {
                                            ts: diag::Timestamp::now(),
                                            state: diag::RoutingState {
                                                selected_proxy: selected_proxy.clone(),
                                            },
                                        });
                                        info!("routing updated via diag cmd");
                                    }
                                    diag::ControlCommand::QueryDnsState => {
                                        let stats = dns_handle.stats();
                                        diag_srv.emit(diag::DiagEvent::DnsState {
                                            ts: diag::Timestamp::now(),
                                            state: diag::DnsState {
                                                aaaa_only: stats.aaaa_only,
                                                domain_count: stats.domain_count,
                                                ip4_count: stats.ip4_count,
                                                ip6_count: stats.ip6_count,
                                            },
                                        });
                                    }
                                    diag::ControlCommand::QueryRoutingState => {
                                        diag_srv.emit(diag::DiagEvent::RoutingState {
                                            ts: diag::Timestamp::now(),
                                            state: diag::RoutingState {
                                                selected_proxy: selected_proxy.clone(),
                                            },
                                        });
                                    }
                                    diag::ControlCommand::QueryHotConfig => {
                                        match tokio::fs::read_to_string(&hot_conf_cmd).await {
                                            Ok(content) => {
                                                diag_srv.emit(diag::DiagEvent::HotConfigSnapshot {
                                                    ts: diag::Timestamp::now(),
                                                    ok: true,
                                                    content: Some(content),
                                                    error: None,
                                                });
                                            }
                                            Err(e) => {
                                                diag_srv.emit(diag::DiagEvent::HotConfigSnapshot {
                                                    ts: diag::Timestamp::now(),
                                                    ok: false,
                                                    content: None,
                                                    error: Some(e.to_string()),
                                                });
                                            }
                                        }
                                    }
                                    diag::ControlCommand::ApplyHotConfig { content } => {
                                        match serde_json::from_str::<HotConfig>(&content) {
                                            Ok(cfg) => {
                                                if tokio::fs::write(&hot_conf_cmd, &content).await.is_ok() {
                                                    let _ = hot_tx.send(cfg);
                                                    let _ = reload_tx.send(nsproxy_core::hot_reload::HotReloadTrigger::DirectReload).await;
                                                    diag_srv.emit(diag::DiagEvent::HotConfigSnapshot {
                                                        ts: diag::Timestamp::now(),
                                                        ok: true,
                                                        content: Some(content),
                                                        error: None,
                                                    });
                                                } else {
                                                    diag_srv.emit(diag::DiagEvent::HotConfigSnapshot {
                                                        ts: diag::Timestamp::now(),
                                                        ok: false,
                                                        content: None,
                                                        error: Some("failed to write hot config".to_string()),
                                                    });
                                                }
                                            }
                                            Err(e) => {
                                                diag_srv.emit(diag::DiagEvent::HotConfigSnapshot {
                                                    ts: diag::Timestamp::now(),
                                                    ok: false,
                                                    content: None,
                                                    error: Some(e.to_string()),
                                                });
                                            }
                                        }
                                    }
                                    diag::ControlCommand::QueryUplinkStats => {
                                        let hub = uplink_cmd.read().await;
                                        diag_srv.emit(diag::DiagEvent::UplinkStatsSnapshot {
                                            ts: diag::Timestamp::now(),
                                            stats: hub.stats.clone(),
                                        });
                                    }
                                    diag::ControlCommand::ClearStats => {
                                        let mut hub = uplink_cmd.write().await;
                                        hub.clear_stats();

                                        if let Err(e) = hub.save_stats() {
                                            warn!("failed to save cleared stats: {}", e);
                                        } else {
                                            info!("uplink stats cleared via diag cmd");
                                        }

                                        diag_srv.emit(diag::DiagEvent::UplinkStatsSnapshot {
                                            ts: diag::Timestamp::now(),
                                            stats: hub.stats.clone(),
                                        });
                                    }
                                    diag::ControlCommand::QueryRecentLogs { limit } => {
                                        let entries = diag::query_recent_logs(limit);
                                        diag_srv.emit(diag::DiagEvent::RecentLogs(entries));
                                    }
                                    // Handled directly inside serve_client; should never reach here.
                                    diag::ControlCommand::QueryRecentDiagEvents { .. } => {}
                                    diag::ControlCommand::SetTrackConns { .. } => {}
                                    diag::ControlCommand::ResetConnsState => {}
                                    diag::ControlCommand::QueryConnsState => {}
                                }
                            }
                        }));
                    }

                    let _ = vdns_sx.send(Some(router.dns_handle())).await;

                    let diag_srv = router.diag_handle();
                    let hot_tx_spawn = hot_tx.clone();
                    tokio::spawn(scope_for_watch.scope(async move {
                        let x = watch_hot(
                            vdns_rx,
                            Some(hot_conf),
                            acceptor,
                            child_pid as u32,
                            tx,
                            None,
                            diag_srv,
                            hot_reload_rx,
                            hot_tx_spawn,
                        )
                        .await;
                        warn!("out-ns, watcher exited {:?}", x);
                    }));

                    router.run().await?;
                    warn!("router exited");
                    let _ = vdns_sx.send(None).await;

                    std::future::pending::<()>().await;
                    aok!()
                    }).await
                })?;
            }
        },
        Err(er) => report_clone3_err(&er)?,
    }

    Ok(())
}

use anyhow::{Result, anyhow, bail};
use arc_swap::ArcSwap;

/// Shared mutable state for the `sp up` daemon.
#[derive(Clone)]
struct UpDaemonState {
    process_list: diag::ProcessList,
    /// PID of the currently-tracked `sp serve` process (0 = none).
    /// The corresponding entry in `process_list.processes` carries the
    /// live `ProcessStatus`; this field is the look-up key.
    serve_pid: u32,
}

pub fn try_resolve_nsinput(nsi: NsInput) -> Result<Option<ExactNS>> {
    match nsi {
        NsInput::Path(p) => Ok(Some(NSFrom::from_source(p)?)),
        NsInput::Pid(p) => Ok(Some(NSFrom::from_source(p)?)),
        _ => Ok(None),
    }
}

async fn handle_socks5_connection<S>(
    conn: socks5_impl::server::IncomingConnection<S>,
) -> anyhow::Result<()>
where
    S: Send + Sync + 'static,
{
    use socks5_impl::protocol::*;
    use socks5_impl::server::*;
    use tokio::io;
    use tokio::net::TcpStream;

    let (conn, res) = conn.authenticate().await?;

    match conn.wait_request().await? {
        ClientConnection::UdpAssociate(associate, _) => {
            info!("UDP associate not supported");
            let mut conn = associate
                .reply(Reply::CommandNotSupported, WireAddress::unspecified())
                .await?;
            conn.shutdown().await?;
        }
        ClientConnection::Bind(bind, _) => {
            info!("Bind not supported");
            let mut conn = bind
                .reply(Reply::CommandNotSupported, WireAddress::unspecified())
                .await?;
            conn.shutdown().await?;
        }
        ClientConnection::Connect(connect, addr) => {
            info!("connect to {}", addr);
            let target = match &addr {
                WireAddress::DomainAddress(domain, port) => {
                    TcpStream::connect((domain.as_str(), *port)).await
                }
                WireAddress::SocketAddress(socket_addr) => TcpStream::connect(socket_addr).await,
            };

            match target {
                Ok(mut target_stream) => {
                    let mut conn = connect
                        .reply(Reply::Succeeded, WireAddress::unspecified())
                        .await?;
                    info!("established connection to {}", addr);
                    io::copy_bidirectional(&mut target_stream, &mut conn).await?;
                }
                Err(err) => {
                    warn!("failed to connect to {}: {}", addr, err);
                    let mut conn = connect
                        .reply(Reply::HostUnreachable, WireAddress::unspecified())
                        .await?;
                    conn.shutdown().await?;
                }
            }
        }
    }

    Ok(())
}

/// Accept loop for the `sp up` daemon socket.
///
/// Always accepts new connections and serves each in its own handler task.
/// The shared `UpDaemonState` is passed as `Arc<ArcSwap<…>>` so handlers can
/// do lock-free load/store updates without a mutex.
async fn run_up_daemon(
    profile: &str,
    ns_meta: PathBuf,
    keeper_pid: u32,
    control_socket: Option<PathBuf>,
    simulate_protocol_no_upgrade: bool,
    simulate_conn_close: bool,
    simulate_slow_shutdown: bool,
) -> Result<()> {
    let sock_path = diag::up_sock_path(profile);
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&sock_path);

    let listener = tokio::net::UnixListener::bind(&sock_path)?;
    std::fs::set_permissions(&sock_path, Permissions::from_mode(0o666))?;
    info!("up-daemon listening on {:?}", sock_path);

    // Initialise the global log broadcast so DiagTracingLayer can forward
    // tracing events from outside any serve scope to the connected UI client.
    diag::init_up_log_broadcast();

    let state: Arc<ArcSwap<UpDaemonState>> = Arc::new(ArcSwap::new(Arc::new(UpDaemonState {
        process_list: diag::ProcessList {
            processes: BTreeMap::new(),
        },
        serve_pid: 0,
    })));

    // Shared per-process stdout/stderr ring buffer.
    let raw_logs: Arc<Mutex<BTreeMap<u32, VecDeque<diag::RawLog>>>> =
        Arc::new(Mutex::new(BTreeMap::new()));
    // Shared PTY byte scrollback ring per process.
    let pty_scrollback: Arc<Mutex<BTreeMap<u32, VecDeque<u8>>>> =
        Arc::new(Mutex::new(BTreeMap::new()));
    // PTY master fd per process for input/resize control.
    let pty_masters: Arc<Mutex<BTreeMap<u32, OwnedFd>>> = Arc::new(Mutex::new(BTreeMap::new()));
    // PTY output broadcast channels keyed by process pid.
    let pty_streams: Arc<Mutex<BTreeMap<u32, tokio::sync::broadcast::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(BTreeMap::new()));
    // Daemon-level broadcast for process exit notifications.  Hoisted out of
    // handle_up_client so that watcher tasks spawned on an older connection
    // survive a reconnect and can still update state and notify the new client.
    let (exit_broadcast_tx, _) = tokio::sync::broadcast::channel::<u32>(64);
    let exit_broadcast_tx: Arc<tokio::sync::broadcast::Sender<u32>> = Arc::new(exit_broadcast_tx);

    // If the UI passed a control socket path, connect to it immediately and serve it
    // as a reversed-role client.  This is event-triggered: the UI doesn't need to
    // poll our socket; we initiate the connection and it receives DaemonEvent frames
    // just as if it had connected to us.
    if simulate_conn_close {
        warn!(
            profile,
            "up daemon mock mode active: simulate_conn_close=true, skipping reversed control-socket connection"
        );
    } else if let Some(ref ctrl_path) = control_socket {
        let ctrl_path = ctrl_path.clone();
        let profile_name = profile.to_string();
        let state2 = state.clone();
        let ns_meta2 = ns_meta.clone();
        let log_rx2 = diag::subscribe_up_logs()
            .expect("up log broadcast must be initialised before control socket connect");
        let raw_logs2 = raw_logs.clone();
        let pty_scrollback2 = pty_scrollback.clone();
        let pty_masters2 = pty_masters.clone();
        let pty_streams2 = pty_streams.clone();
        let exit_broadcast2 = Arc::clone(&exit_broadcast_tx);
        tokio::spawn(async move {
            match connect_and_greet_up(&ctrl_path, &profile_name).await {
                Ok(stream) => {
                    info!("up daemon: connected to UI control socket, serving reversed connection");
                    if let Err(e) = handle_up_client(
                        stream,
                        state2,
                        ns_meta2,
                        keeper_pid,
                        simulate_protocol_no_upgrade,
                        simulate_slow_shutdown,
                        log_rx2,
                        raw_logs2,
                        pty_scrollback2,
                        pty_masters2,
                        pty_streams2,
                        exit_broadcast2,
                    ).await {
                        warn!("up daemon reversed client error: {}", e);
                    }
                }
                Err(e) => warn!("up daemon: failed to connect to control socket {:?}: {}", ctrl_path, e),
            }
        });
    }

    loop {
        let (mut stream, _addr) = listener.accept().await?;

        if simulate_conn_close {
            warn!(profile, "up daemon mock mode: simulate_conn_close=true, dropping accepted connection");
            continue;
        }

        if let Err(e) = diag::handshake_server(&mut stream, diag::ProtocolChannel::Up).await {
            warn!("up daemon handshake failed: {}", e);
            continue;
        }

        let state = state.clone();
        let ns_meta = ns_meta.clone();
        // Subscribe to the log broadcast for this new connection.
        let log_rx = diag::subscribe_up_logs()
            .expect("up log broadcast must be initialised before accept loop");
        let raw_logs_conn = raw_logs.clone();
        let pty_scrollback_conn = pty_scrollback.clone();
        let pty_masters_conn = pty_masters.clone();
        let pty_streams_conn = pty_streams.clone();
        let exit_broadcast_conn = Arc::clone(&exit_broadcast_tx);
        tokio::spawn(async move {
            if let Err(e) = handle_up_client(
                stream,
                state,
                ns_meta,
                keeper_pid,
                simulate_protocol_no_upgrade,
                simulate_slow_shutdown,
                log_rx,
                raw_logs_conn,
                pty_scrollback_conn,
                pty_masters_conn,
                pty_streams_conn,
                exit_broadcast_conn,
            ).await {
                warn!("up daemon client error: {}", e);
            }
        });
    }
}

/// Spawn a blocking thread that reads lines from `fd` and appends them to the per-process
/// raw log ring buffer.  The thread exits automatically when the write end of the pipe is
/// closed (i.e. when the process exits).
fn spawn_pipe_reader(
    pid: u32,
    kind: diag::RawLogKind,
    fd: std::os::unix::io::RawFd,
    raw_logs: Arc<Mutex<BTreeMap<u32, VecDeque<diag::RawLog>>>>,
) {
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        use std::os::unix::io::FromRawFd;
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let reader = BufReader::new(file);
        for line in reader.lines() {
            match line {
                Ok(content) => {
                    let entry = diag::RawLog {
                        ts: diag::Timestamp::now(),
                        kind,
                        content,
                    };
                    if let Ok(mut guard) = raw_logs.lock() {
                        let ring = guard
                            .entry(pid)
                            .or_insert_with(|| VecDeque::with_capacity(diag::RAW_LOG_RING_CAP));
                        if ring.len() >= diag::RAW_LOG_RING_CAP {
                            ring.pop_front();
                        }
                        ring.push_back(entry);
                    }
                }
                Err(_) => break,
            }
        }
    });
}

fn append_pty_scrollback(ring: &mut VecDeque<u8>, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let overflow = ring
        .len()
        .saturating_add(data.len())
        .saturating_sub(PTY_SCROLLBACK_CAP);
    for _ in 0..overflow {
        ring.pop_front();
    }
    ring.extend(data.iter().copied());
}

/// Scan `chunk` for DA1 (`ESC [ c` / `ESC [ 0 c`) and DA2 (`ESC [ > c` / `ESC [ > 0 c`)
/// terminal-capability query sequences sent by the child process. For each found, write
/// the appropriate response directly back to `file` (the PTY master fd is bidirectional).
/// Returns the chunk with those sequences removed, or `None` if no changes were needed.
/// Responding here avoids the UI round-trip latency that causes the delayed response to
/// arrive after fish has already moved on and prints the escape bytes as literal text.
fn intercept_terminal_queries(file: &mut std::fs::File, chunk: &[u8]) -> Option<Vec<u8>> {
    let mut out: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < chunk.len() {
        if chunk[i] == 0x1b && chunk.get(i + 1) == Some(&b'[') {
            // DA1: ESC [ c
            if chunk.get(i + 2) == Some(&b'c') {
                let _ = file.write_all(b"\x1b[?6c");
                out.get_or_insert_with(|| chunk[..i].to_vec());
                i += 3;
                continue;
            }
            // DA1: ESC [ 0 c
            if chunk.get(i + 2) == Some(&b'0') && chunk.get(i + 3) == Some(&b'c') {
                let _ = file.write_all(b"\x1b[?6c");
                out.get_or_insert_with(|| chunk[..i].to_vec());
                i += 4;
                continue;
            }
            // DA2: ESC [ > c
            if chunk.get(i + 2) == Some(&b'>') && chunk.get(i + 3) == Some(&b'c') {
                let _ = file.write_all(b"\x1b[>0;10;1c");
                out.get_or_insert_with(|| chunk[..i].to_vec());
                i += 4;
                continue;
            }
            // DA2: ESC [ > 0 c
            if chunk.get(i + 2) == Some(&b'>')
                && chunk.get(i + 3) == Some(&b'0')
                && chunk.get(i + 4) == Some(&b'c')
            {
                let _ = file.write_all(b"\x1b[>0;10;1c");
                out.get_or_insert_with(|| chunk[..i].to_vec());
                i += 5;
                continue;
            }
        }
        if let Some(ref mut v) = out {
            v.push(chunk[i]);
        }
        i += 1;
    }
    out
}

fn spawn_pty_relay(
    pid: u32,
    relay_fd: OwnedFd,
    pty_scrollback: Arc<Mutex<BTreeMap<u32, VecDeque<u8>>>>,
    pty_streams: Arc<Mutex<BTreeMap<u32, tokio::sync::broadcast::Sender<Vec<u8>>>>>,
) {
    std::thread::spawn(move || {
        let mut file = std::fs::File::from(relay_fd);
        let mut buf = [0_u8; 4096];
        loop {
            let n = match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let chunk = &buf[..n];

            // Respond to DA1/DA2 terminal queries immediately and strip them
            // from the broadcast so the UI doesn't generate a second, delayed response.
            let filtered = intercept_terminal_queries(&mut file, chunk);
            let broadcast_chunk: &[u8] = filtered.as_deref().unwrap_or(chunk);
            if broadcast_chunk.is_empty() {
                continue;
            }

            {
                let mut guard = pty_scrollback.lock().unwrap_or_else(|e| e.into_inner());
                let ring = guard
                    .entry(pid)
                    .or_insert_with(|| VecDeque::with_capacity(PTY_SCROLLBACK_CAP));
                append_pty_scrollback(ring, broadcast_chunk);
            }

            let tx_opt = {
                let guard = pty_streams.lock().unwrap_or_else(|e| e.into_inner());
                guard.get(&pid).cloned()
            };
            if let Some(tx) = tx_opt {
                let _ = tx.send(broadcast_chunk.to_vec());
            }
        }
    });
}

/// Per-connection handler for the `sp up` daemon.
async fn handle_up_client(
    stream: tokio::net::UnixStream,
    state: Arc<ArcSwap<UpDaemonState>>,
    ns_meta: PathBuf,
    keeper_pid: u32,
    simulate_protocol_no_upgrade: bool,
    simulate_slow_shutdown: bool,
    mut log_rx: tokio::sync::broadcast::Receiver<Arc<Vec<u8>>>,
    raw_logs: Arc<Mutex<BTreeMap<u32, VecDeque<diag::RawLog>>>>,
    pty_scrollback: Arc<Mutex<BTreeMap<u32, VecDeque<u8>>>>,
    pty_masters: Arc<Mutex<BTreeMap<u32, OwnedFd>>>,
    pty_streams: Arc<Mutex<BTreeMap<u32, tokio::sync::broadcast::Sender<Vec<u8>>>>>,
    exit_broadcast_tx: Arc<tokio::sync::broadcast::Sender<u32>>,
) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;
    let (mut read_half, mut write_half) = stream.into_split();
    let mut exit_rx = exit_broadcast_tx.subscribe();
    let (pty_evt_tx, mut pty_evt_rx) = tokio::sync::mpsc::unbounded_channel::<diag::DaemonEvent>();
    let mut attached_pty_tasks: HashMap<u32, tokio::task::JoinHandle<()>> = HashMap::new();
    loop {
        tokio::select! {
            req_result = read_bincode_frame_async::<diag::UpWireRequest, _>(&mut read_half) => {
                let Some(req) = req_result? else {
                    break;
                };

                // Reap before dispatching so that GetProcessList returns
                // the freshest state (catches children that exited since
                // the last event loop iteration).
                reap_dead_children_into_state(&state);

                let req = match req {
                    diag::UpWireRequest::Stable(stable_req) => {
                        warn!(req = ?stable_req, "up daemon: received stable request");
                        match stable_req {
                            diag::StableRequest::Ping => {
                                warn!("up daemon stable step: responding to ping");
                                let stable_evt = diag::StableEvent::Pong;
                                let _ = write_up_stable_frame(&mut write_half, &stable_evt).await;
                            }
                            diag::StableRequest::GracefulShutdown => {
                                warn!("up daemon stable step: graceful shutdown requested");
                                if simulate_slow_shutdown {
                                    warn!("up daemon mock mode: simulate_slow_shutdown=true, delaying graceful shutdown acknowledgement by 6s");
                                    sleep(Duration::from_secs(6)).await;
                                }
                                let stable_evt = diag::StableEvent::ShuttingDown;
                                let _ = write_up_stable_frame(&mut write_half, &stable_evt).await;
                                warn!("up daemon stable step: shutdown acknowledgement sent; stopping daemon");

                                if perform_up_daemon_stop(&state, keeper_pid).await {
                                    std::process::exit(0);
                                }
                            }
                            diag::StableRequest::Upgrade { build_tree_hash } => {
                                warn!(
                                    remote_hash = %build_tree_hash,
                                    local_hash = %nsproxy_core::build_tree_hash(),
                                    "up daemon stable step: protocol upgrade requested"
                                );
                                if simulate_protocol_no_upgrade {
                                    warn!("up daemon mock mode: simulate_protocol_no_upgrade=true, forcing upgrade rejection");
                                    let stable_evt = diag::StableEvent::UpgradeRejected {
                                        msg: "simulated no-upgrade mode".to_string(),
                                    };
                                    write_up_stable_frame(&mut write_half, &stable_evt).await?;
                                    continue;
                                }
                                let local_hash = nsproxy_core::build_tree_hash();
                                if build_tree_hash == local_hash {
                                    warn!("up daemon stable step: upgrade accepted");
                                    let stable_evt = diag::StableEvent::UpgradeAccepted {
                                        build_tree_hash: local_hash.to_string(),
                                    };
                                    write_up_stable_frame(&mut write_half, &stable_evt).await?;
                                } else {
                                    warn!("up daemon stable step: upgrade rejected (hash mismatch)");
                                    let stable_evt = diag::StableEvent::UpgradeRejected {
                                        msg: format!(
                                            "build hash mismatch: local={}, remote={}",
                                            local_hash, build_tree_hash
                                        ),
                                    };
                                    write_up_stable_frame(&mut write_half, &stable_evt).await?;
                                }
                            }
                        }
                        continue;
                    }
                    diag::UpWireRequest::Unstable(req) => req,
                };

                match req {
                    diag::DaemonRequest::GetProcessList => {
                        let s = state.load();
                        let evt = diag::DaemonEvent::ProcessListSnapshot(diag::ProcessListSnapshot {
                            procs: s.process_list.processes.clone(),
                            serve: s.serve_pid,
                        });
                        write_up_unstable_frame(&mut write_half, &evt).await?;
                    }
                    diag::DaemonRequest::Kill { pid } => {
                        let _ = nix::sys::signal::kill(
                            Pid::from_raw(pid as i32),
                            nix::sys::signal::Signal::SIGTERM,
                        );
                        let mut new = (*state.load_full()).clone();
                        if let Some(entry) = new.process_list.processes.get_mut(&pid) {
                            entry.status = diag::ProcessStatus::Terminating(pid);
                        }
                        state.store(Arc::new(new));
                        let s = state.load();
                        let evt = diag::DaemonEvent::ProcessListSnapshot(diag::ProcessListSnapshot {
                            procs: s.process_list.processes.clone(),
                            serve: s.serve_pid,
                        });
                        write_up_unstable_frame(&mut write_half, &evt).await?;
                    }
                    diag::DaemonRequest::Spawn { args } => {
                        let ns_alive = read_ns_alive(&ns_meta)?;
                        let (child, stdout_r, stderr_r) = spawn_daemon_process(&args, &ns_alive)?;
                        let child_pid = match child {
                            Clone3Result::Parent { child_pid, .. } => child_pid as u32,
                            _ => {
                                let evt = diag::DaemonEvent::Error {
                                    msg: "spawn daemon in child context".to_string(),
                                };
                                write_up_unstable_frame(&mut write_half, &evt).await?;
                                reap_dead_children_into_state(&state);
                                continue;
                            }
                        };
                        let mut new = (*state.load_full()).clone();
                        new.process_list.processes.insert(
                            child_pid,
                            diag::ProcessEntry {
                                meta: diag::SpawnedEntry::Args(args),
                                spawned_at: SystemTime::now(),
                                status: diag::ProcessStatus::Alive(child_pid),
                            },
                        );
                        state.store(Arc::new(new));

                        spawn_pipe_reader(child_pid, diag::RawLogKind::Stdout, stdout_r, raw_logs.clone());
                        spawn_pipe_reader(child_pid, diag::RawLogKind::Stderr, stderr_r, raw_logs.clone());

                        let spawned = diag::DaemonEvent::Spawned { pid: child_pid };
                        write_up_unstable_frame(&mut write_half, &spawned).await?;
                        let s = state.load();
                        let snapshot = diag::DaemonEvent::ProcessListSnapshot(diag::ProcessListSnapshot {
                            procs: s.process_list.processes.clone(),
                            serve: s.serve_pid,
                        });
                        write_up_unstable_frame(&mut write_half, &snapshot).await?;

                        let exit_tx2 = Arc::clone(&exit_broadcast_tx);
                        let state_w = state.clone();
                        tokio::spawn(async move {
                            wait_for_child_exit_async(child_pid).await;
                            let mut new = (*state_w.load_full()).clone();
                            if let Some(entry) = new.process_list.processes.get_mut(&child_pid) {
                                entry.status = diag::ProcessStatus::Killed(child_pid);
                            }
                            if new.serve_pid == child_pid {
                                new.serve_pid = 0;
                            }
                            state_w.store(Arc::new(new));
                            info!("child pid {} exited", child_pid);
                            let _ = exit_tx2.send(child_pid);
                        });
                    }
                    diag::DaemonRequest::SpawnCli { cli_bincode, ns } => {
                        let cli = match bincode::deserialize::<Cli>(&cli_bincode) {
                            Ok(cli) => cli,
                            Err(err) => {
                                let evt = diag::DaemonEvent::Error {
                                    msg: format!("invalid cli payload: {err}"),
                                };
                                write_up_unstable_frame(&mut write_half, &evt).await?;
                                reap_dead_children_into_state(&state);
                                continue;
                            }
                        };
                        let is_serve = matches!(&cli.cmd, MainCommand::Serve { .. });
                        let ns_alive = read_ns_alive(&ns_meta)?;
                        let (child_pid, stdout_r, stderr_r) =
                            match spawn_cli_process(&cli, &ns_alive, ns)? {
                            Some((pid, stdout_r, stderr_r)) => (pid, stdout_r, stderr_r),
                            None => {
                                reap_dead_children_into_state(&state);
                                continue;
                            }
                        };
                        let cli_bytes = bincode::serialize(&cli)?;
                        let mut new = (*state.load_full()).clone();
                        new.process_list.processes.insert(
                            child_pid,
                            diag::ProcessEntry {
                                meta: diag::SpawnedEntry::Cli(diag::SpawnCliType {
                                    cli_bincode: cli_bytes,
                                    is_serve,
                                }),
                                spawned_at: SystemTime::now(),
                                status: diag::ProcessStatus::Alive(child_pid),
                            },
                        );
                        if is_serve {
                            new.serve_pid = child_pid;
                        }
                        state.store(Arc::new(new));

                        spawn_pipe_reader(child_pid, diag::RawLogKind::Stdout, stdout_r, raw_logs.clone());
                        spawn_pipe_reader(child_pid, diag::RawLogKind::Stderr, stderr_r, raw_logs.clone());

                        let spawned = diag::DaemonEvent::Spawned { pid: child_pid };
                        write_up_unstable_frame(&mut write_half, &spawned).await?;
                        let s = state.load();
                        let snapshot = diag::DaemonEvent::ProcessListSnapshot(diag::ProcessListSnapshot {
                            procs: s.process_list.processes.clone(),
                            serve: s.serve_pid,
                        });
                        write_up_unstable_frame(&mut write_half, &snapshot).await?;

                        let exit_tx2 = Arc::clone(&exit_broadcast_tx);
                        let state_w = state.clone();
                        tokio::spawn(async move {
                            wait_for_child_exit_async(child_pid).await;
                            let mut new = (*state_w.load_full()).clone();
                            if let Some(entry) = new.process_list.processes.get_mut(&child_pid) {
                                entry.status = diag::ProcessStatus::Killed(child_pid);
                            }
                            if new.serve_pid == child_pid {
                                new.serve_pid = 0;
                            }
                            state_w.store(Arc::new(new));
                            info!("child pid {} exited", child_pid);
                            let _ = exit_tx2.send(child_pid);
                        });
                    }
                    diag::DaemonRequest::SpawnPty { args } => {
                        let ns_alive = read_ns_alive(&ns_meta)?;
                        let (child_pid, master_fd) = spawn_pty_process(&args, &ns_alive)?;
                        let relay_raw = unsafe { libc::dup(master_fd.as_raw_fd()) };
                        if relay_raw < 0 {
                            let evt = diag::DaemonEvent::Error {
                                msg: format!("dup PTY master failed: {}", std::io::Error::last_os_error()),
                            };
                            write_up_unstable_frame(&mut write_half, &evt).await?;
                            reap_dead_children_into_state(&state);
                            continue;
                        }
                        let relay_fd = unsafe { OwnedFd::from_raw_fd(relay_raw) };

                        {
                            let mut guard = pty_masters.lock().unwrap_or_else(|e| e.into_inner());
                            guard.insert(child_pid, master_fd);
                        }
                        {
                            let mut guard = pty_scrollback.lock().unwrap_or_else(|e| e.into_inner());
                            guard
                                .entry(child_pid)
                                .or_insert_with(|| VecDeque::with_capacity(PTY_SCROLLBACK_CAP));
                        }
                        {
                            let mut guard = pty_streams.lock().unwrap_or_else(|e| e.into_inner());
                            guard
                                .entry(child_pid)
                                .or_insert_with(|| tokio::sync::broadcast::channel(PTY_BROADCAST_CAP).0);
                        }

                        spawn_pty_relay(child_pid, relay_fd, pty_scrollback.clone(), pty_streams.clone());

                        let mut new = (*state.load_full()).clone();
                        new.process_list.processes.insert(
                            child_pid,
                            diag::ProcessEntry {
                                meta: diag::SpawnedEntry::Pty(args),
                                spawned_at: SystemTime::now(),
                                status: diag::ProcessStatus::Alive(child_pid),
                            },
                        );
                        state.store(Arc::new(new));

                        let spawned = diag::DaemonEvent::Spawned { pid: child_pid };
                        write_up_unstable_frame(&mut write_half, &spawned).await?;
                        let s = state.load();
                        let snapshot = diag::DaemonEvent::ProcessListSnapshot(diag::ProcessListSnapshot {
                            procs: s.process_list.processes.clone(),
                            serve: s.serve_pid,
                        });
                        write_up_unstable_frame(&mut write_half, &snapshot).await?;

                        let exit_tx2 = Arc::clone(&exit_broadcast_tx);
                        let state_w = state.clone();
                        tokio::spawn(async move {
                            wait_for_child_exit_async(child_pid).await;
                            let mut new = (*state_w.load_full()).clone();
                            if let Some(entry) = new.process_list.processes.get_mut(&child_pid) {
                                entry.status = diag::ProcessStatus::Killed(child_pid);
                            }
                            if new.serve_pid == child_pid {
                                new.serve_pid = 0;
                            }
                            state_w.store(Arc::new(new));
                            info!("child pid {} exited", child_pid);
                            let _ = exit_tx2.send(child_pid);
                        });
                    }
                    diag::DaemonRequest::AttachPty { pid } => {
                        let scrollback = {
                            let guard = pty_scrollback.lock().unwrap_or_else(|e| e.into_inner());
                            guard
                                .get(&pid)
                                .map(|ring| ring.iter().copied().collect::<Vec<u8>>())
                                .unwrap_or_default()
                        };
                        let evt = diag::DaemonEvent::PtyScrollback {
                            pid,
                            data: scrollback,
                        };
                        write_up_unstable_frame(&mut write_half, &evt).await?;

                        let tx_opt = {
                            let guard = pty_streams.lock().unwrap_or_else(|e| e.into_inner());
                            guard.get(&pid).cloned()
                        };
                        if let Some(tx) = tx_opt {
                            if let Some(old) = attached_pty_tasks.remove(&pid) {
                                old.abort();
                            }
                            let mut rx = tx.subscribe();
                            let pty_evt_tx2 = pty_evt_tx.clone();
                            let task = tokio::spawn(async move {
                                loop {
                                    match rx.recv().await {
                                        Ok(data) => {
                                            let _ = pty_evt_tx2.send(diag::DaemonEvent::PtyOutput { pid, data });
                                        }
                                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                                    }
                                }
                            });
                            attached_pty_tasks.insert(pid, task);
                        }
                    }
                    diag::DaemonRequest::DetachPty { pid } => {
                        if let Some(task) = attached_pty_tasks.remove(&pid) {
                            task.abort();
                        }
                    }
                    diag::DaemonRequest::PtyInput { pid, data } => {
                        let write_result = {
                            let guard = pty_masters.lock().unwrap_or_else(|e| e.into_inner());
                            guard
                                .get(&pid)
                                .ok_or_else(|| anyhow!("pty pid {} not found", pid))
                                .and_then(|fd| nix::unistd::write(fd.as_raw_fd(), &data).map(|_| ()).map_err(|e| anyhow!(e)))
                        };
                        if let Err(e) = write_result {
                            let evt = diag::DaemonEvent::Error {
                                msg: format!("pty input failed for pid {}: {}", pid, e),
                            };
                            write_up_unstable_frame(&mut write_half, &evt).await?;
                        }
                    }
                    diag::DaemonRequest::PtyResize { pid, cols, rows } => {
                        let resize_result = {
                            let guard = pty_masters.lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(fd) = guard.get(&pid) {
                                let ws = libc::winsize {
                                    ws_row: rows.max(1),
                                    ws_col: cols.max(1),
                                    ws_xpixel: 0,
                                    ws_ypixel: 0,
                                };
                                let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
                                if rc == 0 {
                                    Ok(())
                                } else {
                                    Err(anyhow!(std::io::Error::last_os_error()))
                                }
                            } else {
                                Err(anyhow!("pty pid {} not found", pid))
                            }
                        };
                        if let Err(e) = resize_result {
                            let evt = diag::DaemonEvent::Error {
                                msg: format!("pty resize failed for pid {}: {}", pid, e),
                            };
                            write_up_unstable_frame(&mut write_half, &evt).await?;
                        }
                    }
                    diag::DaemonRequest::Stop => {
                        if simulate_slow_shutdown {
                            warn!("up daemon mock mode: simulate_slow_shutdown=true, delaying stop response by 6s");
                            sleep(Duration::from_secs(6)).await;
                        }
                        let evt = diag::DaemonEvent::Stopping;
                        let _ = write_up_unstable_frame(&mut write_half, &evt).await;

                        if perform_up_daemon_stop(&state, keeper_pid).await {
                            std::process::exit(0);
                        }
                    }
                    diag::DaemonRequest::Ping => {
                        let evt = diag::DaemonEvent::Pong;
                        let _ = write_up_unstable_frame(&mut write_half, &evt).await;
                    }
                    diag::DaemonRequest::QueryRecentLogs { limit } => {
                        let entries = diag::query_recent_logs(limit);
                        let evt = diag::DaemonEvent::RecentLogs(entries);
                        write_up_unstable_frame(&mut write_half, &evt).await?;
                    }
                    diag::DaemonRequest::QueryRawLogs { pid, limit } => {
                        let logs = {
                            let guard = raw_logs.lock().unwrap_or_else(|e| e.into_inner());
                            guard.get(&pid)
                                .map(|ring| {
                                    let skip = ring.len().saturating_sub(limit);
                                    ring.iter().skip(skip).cloned().collect::<Vec<_>>()
                                })
                                .unwrap_or_default()
                        };
                        let evt = diag::DaemonEvent::RawLogs { pid, logs };
                        write_up_unstable_frame(&mut write_half, &evt).await?;
                    }
                }

                reap_dead_children_into_state(&state);
            }

            exited_pid = exit_rx.recv() => {
                match exited_pid {
                    Ok(pid) => {
                        // State was already updated by the watcher task; just clean up
                        // per-connection PTY resources and push events to the client.
                        if let Some(task) = attached_pty_tasks.remove(&pid) {
                            task.abort();
                        }
                        {
                            let mut guard = pty_masters.lock().unwrap_or_else(|e| e.into_inner());
                            guard.remove(&pid);
                        }
                        {
                            let mut guard = pty_streams.lock().unwrap_or_else(|e| e.into_inner());
                            guard.remove(&pid);
                        }
                        {
                            let mut guard = pty_scrollback.lock().unwrap_or_else(|e| e.into_inner());
                            guard.remove(&pid);
                        }
                        let exit_evt = diag::DaemonEvent::ProcessExit { pid };
                        write_up_unstable_frame(&mut write_half, &exit_evt).await?;
                        let s = state.load();
                        let snapshot = diag::DaemonEvent::ProcessListSnapshot(diag::ProcessListSnapshot {
                            procs: s.process_list.processes.clone(),
                            serve: s.serve_pid,
                        });
                        write_up_unstable_frame(&mut write_half, &snapshot).await?;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("exit broadcast lagged by {}, sending full snapshot", n);
                        let s = state.load();
                        let snapshot = diag::DaemonEvent::ProcessListSnapshot(diag::ProcessListSnapshot {
                            procs: s.process_list.processes.clone(),
                            serve: s.serve_pid,
                        });
                        write_up_unstable_frame(&mut write_half, &snapshot).await?;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }

            pty_evt = pty_evt_rx.recv() => {
                if let Some(evt) = pty_evt {
                    write_up_unstable_frame(&mut write_half, &evt).await?;
                }
            }

            log_result = log_rx.recv() => {
                match log_result {
                    Ok(frame) => {
                        write_half.write_all(&frame).await?;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("up daemon log channel lagged, dropped {} log frames", n);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
    Ok(())
}

async fn write_up_stable_frame<W: tokio::io::AsyncWriteExt + Unpin>(
    stream: &mut W,
    evt: &diag::StableEvent,
) -> Result<()> {
    write_bincode_frame_async(stream, &diag::UpWireEvent::Stable(evt.clone())).await
}

async fn write_up_unstable_frame<W: tokio::io::AsyncWriteExt + Unpin>(
    stream: &mut W,
    evt: &diag::DaemonEvent,
) -> Result<()> {
    write_bincode_frame_async(stream, &diag::UpWireEvent::Unstable(evt.clone())).await
}

async fn perform_up_daemon_stop(state: &Arc<ArcSwap<UpDaemonState>>, keeper_pid: u32) -> bool {
    warn!(keeper_pid, "up daemon stop: begin stop sequence");
    {
        let s = state.load();
        // serve is tracked in process_list.processes under its PID,
        // so .keys() already covers it — no extra chain needed.
        for pid in s.process_list.processes.keys().copied() {
            warn!(pid, "up daemon stop: sending SIGTERM to child");
            let _ = nix::sys::signal::kill(
                Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
    }

    warn!(keeper_pid, "up daemon stop: waiting for keeper process exit");
    let keeper_dead = kill_and_wait_for_exit_async(keeper_pid, Duration::from_secs(5)).await;

    if !keeper_dead {
        warn!("keeper pid {} did not exit within 5 seconds", keeper_pid);
        reap_dead_children_into_state(state);
        return false;
    }

    warn!("up daemon stop: keeper exited; waiting for managed child processes");
    reap_dead_children_into_state(state);
    wait_all_children_async(state, Duration::from_secs(5)).await;
    if any_child_alive(state) {
        warn!("up daemon stop: keeper is dead but children still alive; keeping socket loop running");
        return false;
    }

    warn!("up daemon stop: keeper dead and no child processes alive; exiting daemon");
    true
}

/// Returns `true` if any process recorded in `state` is still alive according to the OS.
/// `Killed` entries are skipped to avoid unnecessary syscalls — they are kept in the map
/// for history but are known dead.
fn any_child_alive(state: &Arc<ArcSwap<UpDaemonState>>) -> bool {
    let s = state.load();
    s.process_list
        .processes
        .iter()
        .filter(|(_, e)| !matches!(e.status, diag::ProcessStatus::Killed(_)))
        .any(|(&pid, _)| unsafe { libc::kill(pid as libc::pid_t, 0) == 0 })
}

/// Wait asynchronously for a child process to exit using `pidfd`.
///
/// Opens a `pidfd` for the process and registers it with Tokio's I/O reactor
/// via `AsyncFd`.  A pidfd becomes `EPOLLIN`-readable the instant the process
/// exits — no polling, no sleep loops.  `waitpid(WNOHANG)` reaps the zombie
/// after the fd fires.
async fn wait_for_child_exit_async(pid: u32) {
    use std::os::unix::io::AsRawFd as _;
    use tokio::io::unix::AsyncFd;
    use tokio::io::Interest;

    let pidfd = unsafe { pidfd::PidFd::open(pid as libc::pid_t, 0) }
        .expect("pidfd_open failed");
    // O_NONBLOCK is required by tokio's AsyncFd.
    unsafe {
        let flags = libc::fcntl(pidfd.as_raw_fd(), libc::F_GETFL, 0);
        libc::fcntl(pidfd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let async_fd = AsyncFd::with_interest(pidfd, Interest::READABLE)
        .expect("AsyncFd creation failed");
    let mut guard = async_fd.readable().await
        .expect("AsyncFd readable wait failed");
    guard.retain_ready();
    // Reap the zombie.
    let _ = nix::sys::wait::waitpid(
        Pid::from_raw(pid as i32),
        Some(nix::sys::wait::WaitPidFlag::WNOHANG),
    );
}

fn reap_dead_children_into_state(state: &Arc<ArcSwap<UpDaemonState>>) {
    let mut dead_pids: Vec<u32> = Vec::new();
    loop {
        match nix::sys::wait::waitpid(
            Pid::from_raw(-1),
            Some(nix::sys::wait::WaitPidFlag::WNOHANG),
        ) {
            Ok(nix::sys::wait::WaitStatus::Exited(pid, _))
            | Ok(nix::sys::wait::WaitStatus::Signaled(pid, _, _)) => {
                if pid.as_raw() > 0 {
                    dead_pids.push(pid.as_raw() as u32);
                }
            }
            _ => break,
        }
    }
    if !dead_pids.is_empty() {
        let mut new = (*state.load_full()).clone();
        for dead in &dead_pids {
            // Mark the entry as Killed rather than removing it so that the UI
            // can see the full process history in the snapshot.
            if let Some(entry) = new.process_list.processes.get_mut(dead) {
                entry.status = diag::ProcessStatus::Killed(*dead);
            }
            // Reset the serve tracker when serve exits.
            if new.serve_pid == *dead {
                new.serve_pid = 0;
            }
        }
        state.store(Arc::new(new));
    }
}

fn spawn_cli_process(
    cli: &Cli,
    ns_alive: &nsproxy_core::NsAlive,
    ns: diag::NamespaceSpawn,
) -> Result<Option<(u32, std::os::unix::io::RawFd, std::os::unix::io::RawFd)>> {
    let exe = std::env::current_exe()?;
    let fd_file = cli_to_inheritable_fd(cli)?;
    let fd = fd_file.as_raw_fd();

    let (stdout_r, stdout_w) = pipe()?;
    let (stderr_r, stderr_w) = pipe()?;

    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            let _ = nix::unistd::close(stdout_w);
            let _ = nix::unistd::close(stderr_w);
            Ok(Some((child.as_raw() as u32, stdout_r, stderr_r)))
        }
        ForkResult::Child => {
            let _ = nix::unistd::close(stdout_r);
            let _ = nix::unistd::close(stderr_r);
            let _ = dup2(stdout_w, 1);
            let _ = dup2(stderr_w, 2);
            let _ = nix::unistd::close(stdout_w);
            let _ = nix::unistd::close(stderr_w);

            if matches!(ns, diag::NamespaceSpawn::Inside) {
                enter_ns(ns_alive, &ns_alive.bind_mount)?;
            }

            let fd_str = fd.to_string();
            let exe_s = exe.to_string_lossy();
            let argv = [to_cstr(exe_s.as_ref()), to_cstr(&fd_str)];
            let envs: Vec<_> = std::env::vars()
                .map(|(k, v)| {
                    let mut s = k;
                    s.push('=');
                    s.push_str(&v);
                    to_cstr(&s)
                })
                .collect();

            let _ = execve(&to_cstr(exe_s.as_ref()), &argv, &envs);
            std::process::exit(127);
        }
    }
}

/// Connect to the UI control socket, send a `ControlSocketGreeting::UpDaemon` frame,
/// and return the stream ready for `handle_up_client`.
async fn connect_and_greet_up(ctrl_path: &Path, profile: &str) -> Result<tokio::net::UnixStream> {
    let mut stream = tokio::net::UnixStream::connect(ctrl_path).await?;
    diag::control_handshake_client(&mut stream).await?;
    let greeting = diag::ControlSocketGreeting::UpDaemon { name: profile.to_string() };
    let frame = diag::encode_control_greeting(&greeting)?;
    use tokio::io::AsyncWriteExt as _;
    stream.write_all(&frame).await?;
    Ok(stream)
}

/// Connect to the UI control socket, send a `ControlSocketGreeting::ServeDaemon` frame,
/// and return the stream ready to be handed to `DiagServer::add_reversed_client`.
async fn connect_and_greet_serve(ctrl_path: &Path, profile: &str) -> Result<tokio::net::UnixStream> {
    let mut stream = tokio::net::UnixStream::connect(ctrl_path).await?;
    diag::control_handshake_client(&mut stream).await?;
    let greeting = diag::ControlSocketGreeting::ServeDaemon { name: profile.to_string() };
    let frame = diag::encode_control_greeting(&greeting)?;
    use tokio::io::AsyncWriteExt as _;
    stream.write_all(&frame).await?;
    Ok(stream)
}

fn spawn_daemon_process(
    args: &diag::SpawnArgs,
    ns_alive: &nsproxy_core::NsAlive,
) -> Result<(Clone3Result, std::os::unix::io::RawFd, std::os::unix::io::RawFd)> {
    let exec = args
        .exec
        .clone()
        .ok_or_else(|| anyhow!("spawn args missing exec"))?;
    let exec_resolved = if exec.contains('/') {
        exec.clone()
    } else {
        match which::which(exec.as_str()) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => exec.clone(),
        }
    };
    let cmd = std::ffi::CString::new(exec_resolved.as_str())?;

    let mut argv: Vec<std::ffi::CString> = if args.args.is_empty() {
        vec![std::ffi::CString::new(exec.as_str())?]
    } else {
        args.args
            .iter()
            .map(|a| std::ffi::CString::new(a.as_str()))
            .collect::<std::result::Result<Vec<_>, _>>()?
    };

    if argv.is_empty() {
        argv.push(std::ffi::CString::new(exec.as_str())?);
    }

    let container_val = ns_alive
        .profile_name
        .clone()
        .unwrap_or_else(|| "UNSPEC".to_string());
    let profile_val = ns_alive
        .browser_profile
        .clone()
        .unwrap_or_else(|| "UNSPEC".to_string());
    let ns_val = ns_alive.bind_mount.to_string_lossy().to_string();
    unsafe {
        std::env::set_var(ENV_CONTAINER, &container_val);
        std::env::set_var(ENV_PROFILE, &profile_val);
        std::env::set_var(ENV_NS, &ns_val);
    }

    let mut env_pairs: Vec<(String, String)> = std::env::vars().collect();
    env_pairs.retain(|(k, _)| k != ENV_CONTAINER && k != ENV_PROFILE && k != ENV_NS);
    env_pairs.push((ENV_CONTAINER.to_string(), container_val));
    env_pairs.push((ENV_PROFILE.to_string(), profile_val));
    env_pairs.push((ENV_NS.to_string(), ns_val));
    let env_c: Vec<std::ffi::CString> = env_pairs
        .into_iter()
        .map(|(k, v)| std::ffi::CString::new(format!("{}={}", k, v)))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let (stdout_r, stdout_w) = pipe()?;
    let (stderr_r, stderr_w) = pipe()?;

    let clone = nsproxy_core::sys::clone3::<false>(false, false)?;
    match &clone {
        Clone3Result::IsChild { .. } => {
            let _ = nix::unistd::close(stdout_r);
            let _ = nix::unistd::close(stderr_r);
            let _ = dup2(stdout_w, 1);
            let _ = dup2(stderr_w, 2);
            let _ = nix::unistd::close(stdout_w);
            let _ = nix::unistd::close(stderr_w);

            if matches!(args.ns, diag::NamespaceSpawn::Inside) {
                enter_ns(ns_alive, &ns_alive.bind_mount)?;
            }

            if !args.gids.is_empty() {
                setgroups(
                    &args
                        .gids
                        .iter()
                        .map(|g| Gid::from_raw(*g))
                        .collect::<Vec<_>>(),
                )?;
            }

            if let Some(gid) = args.gid {
                let g = Gid::from_raw(gid);
                setresgid(g, g, g)?;
            }

            if let Some(uid) = args.uid {
                let u = Uid::from_raw(uid);
                setresuid(u, u, u)?;
            }

            if let Some(cwd) = &args.cwd {
                chdir(cwd)?;
            }

            match execve(cmd.as_c_str(), &argv, &env_c) {
                Ok(_) => unreachable!(),
                Err(e) => {
                    error!("daemon spawn execve failed: {}", e);
                    std::process::exit(127);
                }
            }
        }
        Clone3Result::Parent { .. } => {
            let _ = nix::unistd::close(stdout_w);
            let _ = nix::unistd::close(stderr_w);
        }
    }

    Ok((clone, stdout_r, stderr_r))
}

fn spawn_pty_process(
    args: &diag::SpawnArgs,
    ns_alive: &nsproxy_core::NsAlive,
) -> Result<(u32, OwnedFd)> {
    let exec = args
        .exec
        .clone()
        .ok_or_else(|| anyhow!("spawn args missing exec"))?;
    let exec_resolved = if exec.contains('/') {
        exec.clone()
    } else {
        match which::which(exec.as_str()) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => exec.clone(),
        }
    };
    let cmd = std::ffi::CString::new(exec_resolved.as_str())?;

    let mut argv: Vec<std::ffi::CString> = if args.args.is_empty() {
        vec![std::ffi::CString::new(exec.as_str())?]
    } else {
        args.args
            .iter()
            .map(|a| std::ffi::CString::new(a.as_str()))
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    if argv.is_empty() {
        argv.push(std::ffi::CString::new(exec.as_str())?);
    }

    let container_val = ns_alive
        .profile_name
        .clone()
        .unwrap_or_else(|| "UNSPEC".to_string());
    let profile_val = ns_alive
        .browser_profile
        .clone()
        .unwrap_or_else(|| "UNSPEC".to_string());
    let ns_val = ns_alive.bind_mount.to_string_lossy().to_string();
    unsafe {
        std::env::set_var(ENV_CONTAINER, &container_val);
        std::env::set_var(ENV_PROFILE, &profile_val);
        std::env::set_var(ENV_NS, &ns_val);
    }

    let mut env_pairs: Vec<(String, String)> = std::env::vars().collect();
    env_pairs.retain(|(k, _)| k != ENV_CONTAINER && k != ENV_PROFILE && k != ENV_NS);
    env_pairs.push((ENV_CONTAINER.to_string(), container_val));
    env_pairs.push((ENV_PROFILE.to_string(), profile_val));
    env_pairs.push((ENV_NS.to_string(), ns_val));
    let env_c: Vec<std::ffi::CString> = env_pairs
        .into_iter()
        .map(|(k, v)| std::ffi::CString::new(format!("{}={}", k, v)))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let pty = openpty(None, None)?;
    match unsafe { fork()? } {
        ForkResult::Parent { child } => Ok((child.as_raw() as u32, pty.master)),
        ForkResult::Child => {
            let slave_fd = pty.slave.as_raw_fd();
            let _ = setsid();
            let _ = unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) };
            let _ = dup2(slave_fd, 0);
            let _ = dup2(slave_fd, 1);
            let _ = dup2(slave_fd, 2);

            if matches!(args.ns, diag::NamespaceSpawn::Inside) {
                enter_ns(ns_alive, &ns_alive.bind_mount)?;
            }

            if !args.gids.is_empty() {
                setgroups(
                    &args
                        .gids
                        .iter()
                        .map(|g| Gid::from_raw(*g))
                        .collect::<Vec<_>>(),
                )?;
            }

            if let Some(gid) = args.gid {
                let g = Gid::from_raw(gid);
                setresgid(g, g, g)?;
            }

            if let Some(uid) = args.uid {
                let u = Uid::from_raw(uid);
                setresuid(u, u, u)?;
            }

            if let Some(cwd) = &args.cwd {
                chdir(cwd)?;
            }

            match execve(cmd.as_c_str(), &argv, &env_c) {
                Ok(_) => unreachable!(),
                Err(e) => {
                    error!("pty spawn execve failed: {}", e);
                    std::process::exit(127);
                }
            }
        }
    }
}

fn kill_and_wait_for_exit(pid: u32, timeout: Duration) -> bool {
    if pid == 0 {
        return false;
    }

    let target = Pid::from_raw(pid as i32);
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        if let Err(e) = nix::sys::signal::kill(target, nix::sys::signal::Signal::SIGKILL) {
            match e {
                nix::errno::Errno::ESRCH => {
                    info!("pid {} is gone (no such process)", pid);
                    return true;
                }
                _ => {
                    warn!("failed to send SIGKILL to pid {}: {}", pid, e);
                }
            }
        }

        match nix::sys::wait::waitpid(target, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                // still running
            }
            Ok(nix::sys::wait::WaitStatus::Exited(_, _))
            | Ok(nix::sys::wait::WaitStatus::Signaled(_, _, _)) => {
                info!("pid {} reaped", pid);
                return true;
            }
            Ok(_) => {
                info!("pid {} ended", pid);
                return true;
            }
            Err(nix::errno::Errno::ECHILD) => {
                info!("pid {} ended (ECHILD)", pid);
                return true;
            }
            Err(nix::errno::Errno::ESRCH) => {
                info!("pid {} is gone (ESRCH)", pid);
                return true;
            }
            Err(e) => {
                warn!("waitpid for pid {} failed: {}", pid, e);
            }
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    false
}

fn pid_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    PathBuf::from("/proc").join(pid.to_string()).exists()
}

fn enter_all_profile_namespaces_of_pid(pid: u32) -> Result<()> {
    warn!(pid, "up preflight: entering mount namespace");
    let source = NSSource::Pid(pid as i32);
    source.enter(CloneFlags::CLONE_NEWNS)?;
    warn!(pid, "up preflight: entering network namespace");
    source.enter(CloneFlags::CLONE_NEWNET)?;
    warn!(pid, "up preflight: entering pid namespace");
    source.enter(CloneFlags::CLONE_NEWPID)?;
    warn!(pid, "up preflight: entered all target namespaces");
    Ok(())
}

async fn kill_and_wait_for_exit_async(pid: u32, timeout: Duration) -> bool {
    if pid == 0 {
        return false;
    }

    let target = Pid::from_raw(pid as i32);
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        if let Err(e) = nix::sys::signal::kill(target, nix::sys::signal::Signal::SIGKILL) {
            match e {
                nix::errno::Errno::ESRCH => {
                    info!("pid {} is gone (no such process)", pid);
                    return true;
                }
                _ => {
                    warn!("failed to send SIGKILL to pid {}: {}", pid, e);
                }
            }
        }

        match nix::sys::wait::waitpid(target, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                // still running
            }
            Ok(nix::sys::wait::WaitStatus::Exited(_, _))
            | Ok(nix::sys::wait::WaitStatus::Signaled(_, _, _)) => {
                info!("pid {} reaped", pid);
                return true;
            }
            Ok(_) => {
                info!("pid {} ended", pid);
                return true;
            }
            Err(nix::errno::Errno::ECHILD) => {
                info!("pid {} ended (ECHILD)", pid);
                return true;
            }
            Err(nix::errno::Errno::ESRCH) => {
                info!("pid {} is gone (ESRCH)", pid);
                return true;
            }
            Err(e) => {
                warn!("waitpid for pid {} failed: {}", pid, e);
            }
        }

        sleep(Duration::from_millis(100)).await;
    }

    false
}

/// Wait for all tracked child processes to exit, driving each with
/// `kill_and_wait_for_exit_async` concurrently via `FuturesUnordered`.
/// Updates `state` by reaping dead children when done.
async fn wait_all_children_async(state: &Arc<ArcSwap<UpDaemonState>>, timeout: Duration) {
    use futures::StreamExt as _;

    let pids: Vec<u32> = {
        let s = state.load();
        // serve is stored in process_list.processes under its own PID;
        // no extra chain required.
        s.process_list
            .processes
            .iter()
            .filter(|(_, e)| !matches!(e.status, diag::ProcessStatus::Killed(_)))
            .map(|(&pid, _)| pid)
            .collect()
    };

    if pids.is_empty() {
        return;
    }

    let mut futs: FuturesUnordered<_> = pids
        .into_iter()
        .map(|pid| kill_and_wait_for_exit_async(pid, timeout))
        .collect();

    while futs.next().await.is_some() {}

    reap_dead_children_into_state(state);
}

fn write_bincode_frame<T: Serialize>(stream: &mut UnixStream, val: &T) -> Result<()> {
    let payload = bincode::serialize(val)?;
    stream.write_all(&(payload.len() as u32).to_le_bytes())?;
    stream.write_all(&payload)?;
    Ok(())
}

fn read_bincode_frame<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(Some(bincode::deserialize(&payload)?))
}

async fn write_bincode_frame_async<T: Serialize, W: tokio::io::AsyncWriteExt + Unpin>(
    stream: &mut W,
    val: &T,
) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;
    let payload = bincode::serialize(val)?;
    stream.write_all(&(payload.len() as u32).to_le_bytes()).await?;
    stream.write_all(&payload).await?;
    Ok(())
}

async fn read_bincode_frame_async<T: for<'de> Deserialize<'de>, R: tokio::io::AsyncReadExt + Unpin>(
    stream: &mut R,
) -> Result<Option<T>> {
    use tokio::io::AsyncReadExt as _;
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok(Some(bincode::deserialize(&payload)?))
}

/// Watch a HotConfig JSON file for changes and apply mount operations.
///
/// Runs in a loop, re-reading the file on each data-modify event,
/// and applying any new `mnt` / `mounts` entries.
async fn watch_hot_mounts(hot_path: &Path, vars: nsproxy_core::PathExpansionState) -> Result<()> {
    if !hot_path.exists() {
        info!("hot config {:?} does not exist, skipping watcher", hot_path);
        return Ok(());
    }

    let (mut watcher, mut rx) = {
        let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);
        let watcher = RecommendedWatcher::new(
            move |res: std::result::Result<Event, notify::Error>| {
                if let Ok(res) = res {
                    if matches!(res.kind, EventKind::Modify(ModifyKind::Data(_))) {
                        let _ = tx.try_send(());
                    }
                }
            },
            notify::Config::default(),
        )?;
        (watcher, rx)
    };

    watcher.watch(hot_path, notify::RecursiveMode::NonRecursive)?;
    info!("watching hot config {:?} for mount changes", hot_path);

    let mut prev_hot: Option<HotConfig> = None;

    while let Some(()) = rx.recv().await {
        let fc = match tokio::fs::read_to_string(hot_path).await {
            Ok(fc) => fc,
            Err(e) => {
                warn!("failed to read hot config: {}", e);
                continue;
            }
        };
        let mut hot: HotConfig = match serde_json::from_str(&fc) {
            Ok(h) => h,
            Err(e) => {
                warn!("failed to parse hot config: {}", e);
                continue;
            }
        };

        hot.expand_with(&vars);

        if prev_hot.as_ref() == Some(&hot) {
            continue;
        }

        info!("hot config changed, applying mount updates");
        match hot.merged_mounts() {
            Ok(mounts) => {
                if !mounts.is_empty() {
                    if let Err(e) = nsproxy_core::sandbox::apply_mounts(&vars, &mounts) {
                        warn!("failed to apply hot mounts: {}", e);
                    }
                }
            }
            Err(e) => warn!("failed to merge hot mounts: {}", e),
        }

        prev_hot = Some(hot);
    }

    Ok(())
}
