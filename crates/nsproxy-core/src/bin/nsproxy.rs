#![feature(ip_as_octets)]

use capctl::prctl;
/// This binary will at most spawn 2 processes (including itself)
/// It's intended to be minimal, which can be used later in higher order composition such as in GUI
use clap::{
    CommandFactory, Parser, Subcommand, ValueEnum,
    builder::{TypedValueParser, ValueParser, ValueParserFactory},
};
use clap_complete::{generate, shells::Fish};
use futures::stream::TryStreamExt;
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
    sched::{CloneFlags, unshare},
    unistd::{Gid, Pid, Uid, chown, getresgid, getresuid},
};
use notify::{Event, EventKind, RecommendedWatcher, Watcher, event::ModifyKind};
use nsproxy_common::{ExactNS, NSFrom, NSSource, PidPath, UniqueFile, forever};
use nsproxy_core::{
    BasisCommand, Cli, HotConfig, MainCommand, NetlinkOps, NsproxyConfig, Paths, PathsBinds,
    SandboxMode, TemplateConfig, TunMaker,
    cmd_common::{
        apply_ns_env, check_proxy_mode, enter_ns, read_ns_alive, read_ns_alive_opt,
        report_clone3_err,
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
    env::ENV_PROFILE,
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
    collections::{HashMap, HashSet, hash_map::Entry},
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
    time::Duration,
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

fn main() -> anyhow::Result<()> {
    let mut cli = Cli::parse();
    if let Some(root) = cli.root.clone() {
        state_paths::set_persist_root(root.clone());
        info!("Using state root: {:?}", root);
    }
    // DEBUG is annoying because its filled with TCP retransmission logs
    let (layer, reload_handle) = tracing_subscriber::reload::Layer::new(
        fmt::Layer::new()
            .without_time()
            .with_filter(LevelFilter::INFO),
    );
    // https://docs.rs/tracing-subscriber/latest/tracing_subscriber/layer/trait.Layer.html
    tracing_subscriber::registry().with(layer).init();

    let pid = nix::unistd::Pid::this();

    use rlimit as rl;
    let (soft, hard) = rl::Resource::NOFILE.get()?;
    info!(
        "open file limits, soft={}, hard={}. trying to raise soft limit to max",
        soft, hard
    );
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
            let profile = std::env::var(ENV_PROFILE);
            println!("Browser profile {} {:?}", ENV_PROFILE, profile);
            let ns = std::env::var(ENV_NS);
            println!("Network namespace {} {:?}", ENV_NS, ns);

            let proc = if let Some(pid) = pid {
                let ns_proc = ExactNS::from_source((PidPath::N(pid as i32), "net"))?;
                Some(ns_proc)
            } else {
                None
            };

            if let Ok(ns) = ns {
                if ns != "UNSPEC" {
                    let path = PathBuf::from(ns);
                    let ns = ExactNS::from_source(path)?;
                    let ns_self = ExactNS::from_source((PidPath::Selfproc, "net"))?;
                    println!("env={} proc_self={}", ns.unique, ns_self.unique);
                    if ns.unique == ns_self.unique {
                        println!("network namespace matches claim");
                    } else {
                        warn!("netns mismatch");
                    }

                    if let Some(proc) = proc {
                        println!("PID-{} -> {}", pid.unwrap(), proc.unique);
                        if proc.unique == ns_self.unique {
                            println!("PID-{} = this process, regarding net-ns", pid.unwrap());
                        } else {
                            println!(
                                "PID-{} does NOT match this process, regarding net-ns",
                                pid.unwrap()
                            );
                        }
                    }

                    let mnt = sandbox::assert_mount_ns_isolated();
                    println!(
                        "mount namespace is {}",
                        if mnt.is_ok() {
                            "isolated"
                        } else {
                            "not isolated"
                        }
                    );
                }
            }
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
                        std::fs::write(&path, &buf)?;
                        warn!("Installed fish completion: {:?}", path);
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
        MainCommand::Up { profile } => {
            let profile_path = state_paths::profile_config(&profile);
            if !profile_path.exists() {
                bail!(
                    "profile config does not exist: {:?}. Use 'profile' subcommand to create it.",
                    profile_path
                );
            }
            let profile_conf = TemplateConfig::load(&profile_path)?;

            let bind_mount = state_paths::profile_netns_bind(&profile);
            if let Some(parent) = bind_mount.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let ns_meta = state_paths::profile_ns_meta(&profile);
            if ns_meta.exists() {
                info!("Reading NS metadata from {:?}", &ns_meta);
                if let Ok(content) = std::fs::read_to_string(&ns_meta) {
                    if let Ok(ns_alive) = serde_json::from_str::<nsproxy_core::NsAlive>(&content) {
                        if let Some(pid) = ns_alive.child_pid {
                            let proc_path = PathBuf::from("/proc").join(pid.to_string());
                            if proc_path.exists() {
                                bail!("profile already up; pid {} is alive", pid);
                            }
                        }
                    }
                }
            }

            // Always enter as many namespaces as possible here, since other processes can enter less.
            let clone = nsproxy_core::sys::clone3::<true>(true, true);
            match clone {
                Ok(clone) => match clone {
                    Clone3Result::IsChild { mut tx } => {
                        let mut buf = [0; 1];
                        enable_ping_all()?;
                        tx.read(&mut buf)?; // wait for bind mount

                        // always done when there is new mount namespace
                        mount_bind_root()?;
                        // mounting DNS related things is also basic to either overlay or pivot sandbox
                        mount_resolv_conf("100.68.0.2")?;
                        mount_nsswitch_conf()?;

                        loop {
                            std::thread::park();
                        }
                    }
                    Clone3Result::Parent {
                        child_pid, mut tx, ..
                    } => {
                        if let Some(parent) = bind_mount.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        let path = format!("/proc/{}/ns/net", child_pid);
                        let path = PathBuf::from(path);
                        mount_ns(&path, &bind_mount)?;

                        let ns_alive = nsproxy_core::NsAlive {
                            browser_profile: profile_conf.browser_profile.clone(),
                            bind_mount: bind_mount.clone(),
                            child_pid: Some(child_pid as u32),
                        };
                        let json = serde_json::to_string_pretty(&ns_alive)?;
                        info!(
                            "Writing NS metadata to {:?} ({} bytes)",
                            &ns_meta,
                            json.len()
                        );
                        std::fs::write(&ns_meta, json)?;
                        warn!("Auxiliary data written to {:?}", &ns_meta);

                        tx.write(&[0])?;
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
                                let _ = nix::sys::signal::kill(
                                    nix::unistd::Pid::from_raw(pid as i32),
                                    nix::sys::signal::Signal::SIGKILL,
                                );
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

            // Unmount and remove the bind-mount file.
            if bind_mount.exists() {
                if let Err(e) = rm_mount(&bind_mount) {
                    warn!("failed to remove bind mount {:?}: {:?}", bind_mount, e);
                } else {
                    info!("removed bind mount {:?}", bind_mount);
                }
            } else {
                warn!("bind mount {:?} does not exist, nothing to unmount", bind_mount);
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
        }
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

                    let shared_hot = Arc::new(tokio::sync::RwLock::new(initial_hot));

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

                    if let Some(nym) = simple {
                        let proxy_id = {
                            let uplink = router.uplink().await;
                            uplink.nym_map.get(&nym).cloned().ok_or_else(|| {
                                anyhow!("Simple route proxy not found for nym {}", nym)
                            })?
                        };

                        router
                            .set_routing(nsproxy_core::uplink::simple_routing(proxy_id))
                            .await;
                    }

                    router.init_diag(&diag_path).await?;

                    let _ = vdns_sx.send(Some(router.dns_handle())).await;

                    tokio::spawn(async move {
                        let x = watch_hot(
                            vdns_rx,
                            Some(hot_conf),
                            acceptor,
                            child_pid as u32,
                            tx,
                            None,
                        )
                        .await;
                        warn!("out-ns, watcher exited {:?}", x);
                    });

                    router.run().await?;
                    warn!("router exited");
                    let _ = vdns_sx.send(None).await;

                    std::future::pending::<()>().await;
                    aok!()
                })?;
            }
        },
        Err(er) => report_clone3_err(&er)?,
    }

    Ok(())
}

use anyhow::{Result, anyhow, bail};

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
