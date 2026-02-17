use anyhow::{Context, Result, anyhow, bail};
use owo_colors::OwoColorize;
use socks5_impl::protocol::WireAddress;
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    process::exit,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tun2socks5::{ArgProxy, ProxyType};

use crate::{ClashOps, RemoteOps, UplinkCommand, UplinkInstanceCommand, state_paths};

pub fn load_saved_uplink_hub() -> Result<crate::uplink::UplinkHub> {
    let mut hub = crate::uplink::UplinkHub::new();
    let count = hub.load_saved_proxies()?;

    if count == 0 {
        bail!("No saved proxies found. Import a profile first with 'sp uplink clash profile-add'.");
    }

    Ok(hub)
}

pub fn cmd_uplink(kind: UplinkCommand) -> Result<()> {
    match kind {
        UplinkCommand::Clash { cmd } => cmd_clash(cmd),
        UplinkCommand::Geph => bail!("Geph uplink not yet implemented"),
        UplinkCommand::Instance { name, cmd } => cmd_instance(name, cmd),
        UplinkCommand::Remote { cmd } => cmd_remote(cmd),
    }
}

fn cmd_clash(cmd: ClashOps) -> Result<()> {
    match cmd {
        ClashOps::ConfigAdd { name, path } => clash_config_add(name, path),
        ClashOps::List => clash_list(),
        ClashOps::ConfigExplain { path } => clash_config_explain(path),
        ClashOps::Resolve { direct, refresh } => clash_resolve(direct, refresh),
        ClashOps::TestResolve { direct, query } => clash_test_resolve(direct, query),
    }
}

fn clash_config_add(name: String, path: std::path::PathBuf) -> Result<()> {
    println!("Importing Clash profile '{}'...", name);
    println!("  Config: {:?}", path);

    let mut hub = crate::uplink::UplinkHub::new();
    let _ = hub.hydrate_from_persisted()?;
    let mut clash_state = hub.load_clash_state()?.clone();

    let clash_profile = crate::uplink::clash::ClashProfile::load_file(&name, &path)?;

    let append_report = clash_state.append_profile(&clash_profile)?;
    hub.set_clash_state(clash_state)?;

    println!("\n✓ Profile imported");
    println!("  Tier1 nameservers: {}", clash_profile.tier1_nameservers.len());
    println!("  Tier2 nameservers: {}", clash_profile.tier2_nameservers.len());
    println!("  Proxy servers: {}", clash_profile.proxy_domains.len());
    println!(
        "  Appended tier1 nameservers: {}",
        append_report.added_tier1_nameservers
    );
    println!(
        "  Appended tier2 nameservers: {}",
        append_report.added_tier2_nameservers
    );

    println!("\n✓ Profile '{}' is ready to use", name);
    Ok(())
}

fn clash_list() -> Result<()> {
    let uplink_dir = state_paths::uplink_dir("clash");
    if !uplink_dir.exists() {
        println!("No Clash profiles found");
        return Ok(());
    }

    let profiles: Vec<_> = std::fs::read_dir(&uplink_dir)?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .collect();

    if profiles.is_empty() {
        println!("No Clash profiles found");
        return Ok(());
    }

    println!("Clash Profiles:");

    let mut hub = crate::uplink::UplinkHub::new();
    match hub.load_clash_proxies() {
        Ok(count) => {
            println!("  Loaded {} proxy entries across profiles", count);
            let max_show = 5usize;
            println!("  Proxy nyms (first {}):", max_show);
            for (i, (id, proxy)) in hub.all_proxies().iter().take(max_show).enumerate() {
                if let Some(nym) = hub.get_nym(id) {
                    println!("    {}: {:?} => {:?} => {}", i + 1, id, nym, proxy);
                } else {
                    println!("    {}: {:?} => <no nym> => {}", i + 1, id, proxy);
                }
            }
        }
        Err(e) => {
            println!("  Warning: failed to load proxies: {}", e);
        }
    }

    Ok(())
}

fn clash_resolve(direct: bool, refresh: bool) -> Result<()> {
    use crate::uplink::clash::ClashProfile;

    println!("Resolving Clash profiles and updating resolved state...");

    let uplink_dir = state_paths::uplink_dir("clash");
    if !uplink_dir.exists() {
        println!("No Clash profiles found");
        return Ok(());
    }

    let profiles: Vec<_> = std::fs::read_dir(&uplink_dir)?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .collect();

    if profiles.is_empty() {
        println!("No Clash profiles found");
        return Ok(());
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let interrupted = rt.block_on(async {
        let mut hub = crate::uplink::UplinkHub::new();
        let initial_proxy_count = hub.hydrate_from_persisted()?;
        println!(
            "Hydrated uplink state ({} proxies available)",
            initial_proxy_count
        );

        let mut state = hub.load_clash_state()?.clone();
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let cancel_task_flag = Arc::clone(&cancel_flag);
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                cancel_task_flag.store(true, Ordering::SeqCst);
            }
        });

        let mut interrupted = false;

        for entry in profiles {
            if cancel_flag.load(Ordering::Relaxed) {
                println!("\\nInterrupt received (Ctrl+C). Saving current resolved state...");
                interrupted = true;
                break;
            }

            let profile_name = entry.file_name().to_string_lossy().to_string();
            let config_path = state_paths::uplink_profile_config("clash", &profile_name);
            if !config_path.exists() {
                println!("Skipping {}: config missing", profile_name);
                continue;
            }

            println!("Resolving profile: {}", profile_name);
            let profile = ClashProfile::load_file(&profile_name, &config_path)?;
            let unresolved_before = profile
                .proxy_domains
                .iter()
                .filter(|domain| state.get_latest_proxy_ips(domain).is_none())
                .count();

            println!(
                "  Unresolved proxy domains before resolve: {}",
                unresolved_before
            );

            match profile
                .solve_file(
                    &mut state,
                    Some(&hub),
                    Some(cancel_flag.as_ref()),
                    direct,
                    refresh,
                )
                .await
            {
                Ok(report) => {
                    println!("  resolved_domains={}", report.solved.domains.len());
                    println!(
                        "  metrics cache_hits={} proxied_tier2={} proxied_tier1={} direct_tier2={} direct_tier1={} unresolved={}",
                        report.metrics.cache_hits,
                        report.metrics.resolved_proxy_tier2,
                        report.metrics.resolved_proxy_tier1,
                        report.metrics.resolved_direct_tier2,
                        report.metrics.resolved_direct_tier1,
                        report.metrics.unresolved
                    );
                }
                Err(e) => {
                    println!("  Failed to resolve {}: {}", profile_name, e);
                }
            }
            
            if cancel_flag.load(Ordering::Relaxed) {
                println!("\\nInterrupt received (Ctrl+C). Saving current resolved state...");
                interrupted = true;
                break;
            }
        }

        hub.set_clash_state(state)?;

        if interrupted {
            println!("Saved partial resolved state. Exiting due to interrupt.");
            return Ok::<bool, anyhow::Error>(true);
        }

        let mut hub = crate::uplink::UplinkHub::new();
        let count = hub.hydrate_from_persisted()?;
        println!("Loaded {} proxies from resolved profiles", count);

        Ok::<bool, anyhow::Error>(false)
    })?;

    if interrupted {
        exit(130);
    }

    Ok(())
}

fn clash_test_resolve(direct: bool, query: String) -> Result<()> {
    println!("Testing single domain resolution: {}", query);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let mut hub = crate::uplink::UplinkHub::new();
        let proxy_count = hub.hydrate_from_persisted()?;
        println!("Hydrated uplink state ({} proxies available)", proxy_count);

        let state = hub.load_clash_state()?.clone();
        let report = state
            .resolve_one_domain_no_store(&query, Some(&hub), None, direct)
            .await?;

        if let Some(ips) = report.solved.get_latest_ips(&query) {
            let ips_joined = ips
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            println!(
                "resolved domain={} ip_count={} ips={}",
                query,
                ips.len(),
                ips_joined
            );
        } else {
            println!("resolved domain={} ip_count=0 ips=", query);
        }

        println!(
            "metrics cache_hits={} proxied_tier2={} proxied_tier1={} direct_tier2={} direct_tier1={} unresolved={}",
            report.metrics.cache_hits,
            report.metrics.resolved_proxy_tier2,
            report.metrics.resolved_proxy_tier1,
            report.metrics.resolved_direct_tier2,
            report.metrics.resolved_direct_tier1,
            report.metrics.unresolved
        );

        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

fn clash_config_explain(path: std::path::PathBuf) -> Result<()> {
    use clash_config::Config;

    println!("{}", "Clash Profile Analysis".bold().bright_cyan());
    println!();
    println!("  {}: {}", "Config".dimmed(), path.display());
    println!();

    if !path.exists() {
        bail!("Config file does not exist: {:?}", path);
    }

    let config = Config::try_from(path.clone()).context("Failed to parse Clash YAML config")?;

    println!("{}", "Two-Tier DNS".bold());
    println!();
    println!(
        "  {} {} {} {}",
        "Bootstrap".cyan().bold(),
        "->".dimmed(),
        "Main".cyan().bold(),
        "->".dimmed()
    );
    println!(
        "  {} resolves {} resolves {}",
        "IP nameservers".dimmed(),
        "main tier".dimmed(),
        "proxy domains".dimmed()
    );
    println!();

    let max_show = 3;
    println!(
        "  {} ({} total)",
        "Bootstrap Tier".cyan(),
        config.dns.default_nameserver.len()
    );
    for ns in config.dns.default_nameserver.iter().take(max_show) {
        println!("    {}", ns);
    }
    if config.dns.default_nameserver.len() > max_show {
        println!(
            "    {} ...",
            format!("+{} more", config.dns.default_nameserver.len() - max_show).dimmed()
        );
    }

    println!();
    println!("  {} ({} total)", "Main Tier".cyan(), config.dns.nameserver.len());
    for ns in config.dns.nameserver.iter().take(max_show) {
        println!("    {}", ns);
    }
    if config.dns.nameserver.len() > max_show {
        println!(
            "    {} ...",
            format!("+{} more", config.dns.nameserver.len() - max_show).dimmed()
        );
    }

    let proxies = config
        .proxy
        .as_ref()
        .context("No proxies found in Clash config")?;

    let mut trojan_count = 0;
    let mut other_count = 0;
    let mut proxy_domains: HashSet<String> = HashSet::new();

    for proxy in proxies {
        let proxy_type = proxy
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        if proxy_type == "trojan" {
            trojan_count += 1;
            if let Some(server) = proxy.get("server").and_then(|v| v.as_str()) {
                proxy_domains.insert(server.to_string());
            }
        } else {
            other_count += 1;
        }
    }

    println!();
    println!("{}", "Proxies".bold());
    println!();
    println!("  {}  {}", "Total".dimmed(), proxies.len());
    println!(
        "  {}  {}",
        "Proxy Domains (unique)".dimmed(),
        proxy_domains.len()
    );
    if trojan_count > 0 {
        println!(
            "  {}  {} {}",
            "Trojan".dimmed(),
            trojan_count,
            "(supported)".green()
        );
    } else {
        println!(
            "  {}  {} {}",
            "Trojan".dimmed(),
            trojan_count,
            "(none found)".yellow()
        );
    }
    if other_count > 0 {
        println!(
            "  {}  {} {}",
            "Other".dimmed(),
            other_count,
            "(not supported)".yellow()
        );
    }

    println!();
    println!("{}", "Validation".bold());
    println!();
    let mut valid = true;

    if config.dns.default_nameserver.is_empty() {
        println!("  {} No bootstrap nameservers", "[x]".red().bold());
        valid = false;
    } else {
        let mut all_valid = true;
        for ns in &config.dns.default_nameserver {
            let valid_entry = url::Url::parse(ns).is_ok()
                || ns.parse::<std::net::SocketAddr>().is_ok()
                || ns.parse::<std::net::IpAddr>().is_ok()
                || url::Host::parse(ns).is_ok();

            if !valid_entry {
                println!(
                    "  {} Invalid bootstrap nameserver entry: {}",
                    "[!]".yellow().bold(),
                    ns
                );
                all_valid = false;
            }
        }
        if all_valid {
            println!(
                "  {} Bootstrap nameservers are valid endpoint entries",
                "[✓]".green().bold()
            );
        } else {
            valid = false;
        }
    }

    if trojan_count == 0 {
        println!(
            "  {} No Trojan proxies (only type supported)",
            "[!]".yellow().bold()
        );
        valid = false;
    } else {
        println!("  {} Trojan proxies ({})", "[✓]".green().bold(), trojan_count);
    }

    println!();
    if valid {
        println!("  {} {}", "Status:".bold(), "VALID".green());
    } else {
        println!("  {} {}", "Status:".bold(), "ERRORS".red());
    }
    println!();

    Ok(())
}

fn cmd_remote(cmd: RemoteOps) -> Result<()> {
    match cmd {
        RemoteOps::Add { url } => {
            let proxy = ArgProxy::from_url(&url)?;
            let mut state = crate::uplink::RemoteProxyState::load_or_default()?;

            if state.add_proxy(proxy.clone()) {
                state.save_atomic()?;
                println!("Added remote proxy: {}://{}", proxy.proxy_type, proxy.addr);
            } else {
                println!("Remote proxy already exists: {}", proxy.addr);
            }
        }
        RemoteOps::Remove { nym } => {
            let mut state = crate::uplink::RemoteProxyState::load_or_default()?;
            if state.remove_proxy(&nym) {
                state.save_atomic()?;
                println!("Removed remote proxy: {}", nym);
            } else {
                println!("Remote proxy not found: {}", nym);
            }
        }
        RemoteOps::List => {
            let state = crate::uplink::RemoteProxyState::load_or_default()?;
            if state.proxies.is_empty() {
                println!("No remote proxies saved");
            } else {
                println!("Remote proxies:");
                for (index, proxy) in state.proxies.iter().enumerate() {
                    let id = nsproxy_common::routing::ProxyID::for_remote(proxy.addr);
                    println!(
                        "  {}. {}://{} (nym: {})",
                        index + 1,
                        proxy.proxy_type,
                        proxy.addr,
                        id.nym()
                    );
                }
            }
        }
    }

    Ok(())
}

fn cmd_instance(name: nsproxy_common::routing::ProxyNym, cmd: UplinkInstanceCommand) -> Result<()> {
    match cmd {
        UplinkInstanceCommand::Test => cmd_instance_test(name),
    }
}

fn cmd_instance_test(name: nsproxy_common::routing::ProxyNym) -> Result<()> {
    println!("{}", "Proxy Instance Test".bold().bright_cyan());
    println!();
    println!("  Instance: {}", name.to_string().cyan());
    println!();

    let hub = load_saved_uplink_hub()?;

    println!("Loaded {} proxies", hub.all_proxies().len());
    println!();

    let (proxy_id, proxy) = hub
        .get_proxy_by_nym(&name)
        .ok_or_else(|| anyhow!("Proxy with nym '{}' not found", name))?;

    println!("Found proxy: {:?}", proxy_id);
    println!();

    match proxy {
        crate::uplink::UplinkProxy::Trojan(trojan) => run_trojan_tests(trojan),
        crate::uplink::UplinkProxy::Remote(remote) => run_remote_tests(remote),
        _ => Ok(()),
    }
}

fn run_trojan_tests(trojan: &crate::uplink::clash::TrojanProxy) -> Result<()> {
    println!("{}", "Trojan Proxy Tests".bold());
    println!("  Server: {}", trojan.server_name);
    println!("  Port: {}", trojan.server_addr.port());
    println!();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let state = crate::uplink::clash::ClashState::load_or_default()?;
        let server_ip = state
            .get_latest_proxy_ips(&trojan.server_name)
            .and_then(|ips| ips.iter().next().copied())
            .ok_or_else(|| anyhow!("No resolved IP for {}", trojan.server_name))?;

        println!("{}  Testing TCP connectivity...", "[•]".cyan());
        match trojan.connect_tcp(server_ip, "ip.me", 80).await {
            Ok(crate::uplink::clash::TrojanConnection::TcpConnect(mut stream, _)) => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                let request = "GET / HTTP/1.1\r\nHost: ip.me\r\nConnection: close\r\n\r\n";
                if let Err(e) = stream.write_all(request.as_bytes()).await {
                    println!("{}  TCP test failed: {}", "[✗]".red().bold(), e);
                } else {
                    let mut response = String::new();
                    match tokio::time::timeout(
                        Duration::from_secs(10),
                        stream.read_to_string(&mut response),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            println!("    Raw TCP response ({} bytes):", response.len());
                            for line in response.lines() {
                                println!("      {}", line);
                            }

                            if response.contains("200 OK") || !response.is_empty() {
                                println!(
                                    "{}  TCP test passed (ip.me responded)",
                                    "[✓]".green().bold()
                                );
                            } else {
                                println!(
                                    "{}  TCP test failed: invalid response",
                                    "[✗]".red().bold()
                                );
                            }
                        }
                        Ok(Err(e)) => {
                            println!("{}  TCP test failed: {}", "[✗]".red().bold(), e);
                        }
                        Err(_) => {
                            println!("{}  TCP test failed: timeout", "[✗]".red().bold());
                        }
                    }
                }
            }
            Ok(_) => {
                println!(
                    "{}  TCP test failed: wrong connection type",
                    "[✗]".red().bold()
                );
            }
            Err(e) => {
                println!("{}  TCP test failed: {}", "[✗]".red().bold(), e);
            }
        }

        println!("{}  Testing UDP connectivity...", "[•]".cyan());
        match crate::uplink::proxy_adapters::TrojanAdapter::connect_udp(
            trojan,
            "1.1.1.1",
            53,
            trojan.server_addr.ip(),
        )
        .await
        {
            Ok(crate::uplink::proxy_adapters::ProxyConnection::Udp(mut tunnel)) => {
                let dns_server = WireAddress::SocketAddress(SocketAddr::new(
                    "1.1.1.1".parse::<IpAddr>()?,
                    53,
                ));
                match crate::uplink::proxy_dns::query_via_udp(
                    tunnel.as_mut(),
                    &dns_server,
                    "ip.me",
                    Duration::from_secs(5),
                )
                .await
                {
                    Ok(ips) => {
                        println!("{}  UDP test passed (resolved): {:?}", "[✓]".green().bold(), ips);
                    }
                    Err(e) => {
                        println!("{}  UDP test failed: {}", "[✗]".red().bold(), e);
                    }
                }
            }
            Ok(_) => {
                println!(
                    "{}  UDP test failed: wrong connection type",
                    "[✗]".red().bold()
                );
            }
            Err(e) => {
                println!("{}  UDP test failed: {}", "[✗]".red().bold(), e);
            }
        }

        println!();
        println!("{}", "Test complete".bold());
        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

fn run_remote_tests(remote: &ArgProxy) -> Result<()> {
    println!("{}", "Remote Proxy Tests".bold());
    println!("  Type: {}", remote.proxy_type);
    println!("  Addr: {}", remote.addr);
    println!();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        match remote.proxy_type {
            ProxyType::Socks5 => run_remote_socks5_tests(remote).await,
            ProxyType::Socks4 | ProxyType::Http => Ok(()),
        }
    })?;

    println!();
    println!("{}", "Test complete".bold());
    Ok(())
}

async fn run_remote_socks5_tests(remote: &ArgProxy) -> Result<()> {
    test_remote_socks5_tcp(remote).await;
    test_remote_socks5_udp(remote).await;
    Ok(())
}

async fn test_remote_socks5_tcp(remote: &ArgProxy) {
    use crate::uplink::proxy_adapters::{ProxyConnection, RemoteAdapter};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    println!("{}  Testing TCP connectivity...", "[•]".cyan());
    match RemoteAdapter::connect_tcp(remote, "ip.me", 80).await {
        Ok(ProxyConnection::Tcp(mut stream)) => {
            println!("  TCP connected");
            let request = "GET / HTTP/1.1\r\nHost: ip.me\r\nConnection: close\r\n\r\n";
            if let Err(e) = stream.write_all(request.as_bytes()).await {
                println!("{}  TCP test failed: {:?}", "[✗]".red().bold(), e);
                return;
            }

            let mut response = String::new();
            match tokio::time::timeout(Duration::from_secs(10), stream.read_to_string(&mut response)).await {
                Ok(Ok(_)) => {
                    if response.contains("200 OK") || !response.is_empty() {
                        println!("{}", response);
                        println!("{}  TCP test passed (ip.me responded)", "[✓]".green().bold());
                    } else {
                        println!("{}  TCP test failed: invalid response", "[✗]".red().bold());
                    }
                }
                Ok(Err(e)) => {
                    println!("{}  TCP test failed: {}", "[✗]".red().bold(), e);
                }
                Err(_) => {
                    println!("{}  TCP test failed: timeout", "[✗]".red().bold());
                }
            }
        }
        Ok(_) => {
            println!("{}  TCP test failed: wrong connection type", "[✗]".red().bold());
        }
        Err(e) => {
            println!("{}  TCP test failed: {}", "[✗]".red().bold(), e);
        }
    }
}

async fn test_remote_socks5_udp(remote: &ArgProxy) {
    use crate::uplink::proxy_adapters::{ProxyConnection, RemoteAdapter};

    println!("{}  Testing UDP connectivity...", "[•]".cyan());
    match RemoteAdapter::connect_udp(remote).await {
        Ok(ProxyConnection::Udp(mut tunnel)) => {
            let dns_server = WireAddress::SocketAddress(SocketAddr::new(
                "1.1.1.1".parse().unwrap(),
                53,
            ));

            match crate::uplink::proxy_dns::query_via_udp(
                tunnel.as_mut(),
                &dns_server,
                "ip.me",
                Duration::from_secs(5),
            )
            .await
            {
                Ok(ips) => {
                    println!("{}  UDP test passed (resolved): {:?}", "[✓]".green().bold(), ips);
                }
                Err(e) => {
                    println!("{}  UDP test failed: {}", "[✗]".red().bold(), e);
                }
            }
        }
        Ok(_) => {
            println!("{}  UDP test failed: wrong connection type", "[✗]".red().bold());
        }
        Err(e) => {
            println!("{}  UDP test failed: {}", "[✗]".red().bold(), e);
        }
    }
}
