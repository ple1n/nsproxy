use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::generate;
use clap_complete_nushell::Nushell;
use futures::{StreamExt, future::join_all, stream::FuturesUnordered};
use rand::{distr::Distribution, rng};
use std::{
    collections::HashSet,
    error::Error,
    io,
    time::{Duration, UNIX_EPOCH},
};
use tokio::{task, time::sleep};

/// Simple HTTP client with clap
#[derive(Parser)]
#[command(name = "httpcli")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a single request
    One {
        /// URL to request
        #[arg(default_value = "http://100.68.0.2")]
        url: String,
    },

    /// Fire multiple requests
    Many {
        /// URL to request
        #[arg(default_value = "http://100.68.0.2")]
        url: String,

        /// Number of requests
        #[arg(short, long, default_value_t = 100)]
        count: usize,

        /// Test socks5 only
        #[arg(short, long)]
        proxy: bool,
    },

    /// Generate completions for Nushell
    Completions,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::One { url } => {
            println!("Request at {:?}", UNIX_EPOCH.elapsed()?.as_millis());
            let response = reqwest::get(&url).await?;
            println!("Response: {}", response.text().await?);
        }
        Commands::Many { url, count, proxy } => {
            println!("Firing {} requests to {}", count, url);
            let mut handles = FuturesUnordered::new();
            let c = if proxy {
                reqwest::Client::builder()
                    .proxy(reqwest::Proxy::http("socks5h://127.0.0.1:2080")?)
                    .build()?
            } else {
                reqwest::Client::builder().build()?
            };
            let mut rng = rng();
            // This matches real usage more closely
            let dist = rand::distr::Uniform::new(Duration::from_millis(0), Duration::from_millis(1000))?;
            for _ in 0..count {
                let url = url.clone();
                let req = c.get(url);
                let delay = dist.sample(&mut rng);
                handles.push(async move {
                    sleep(delay).await;
                    let resp = req.send().await;
                    resp
                });
            }
            let mut errs = 0;
            let mut counted = 0;
            let mut strings = HashSet::new();

            while let Some(h) = handles.next().await {
                let rx = h;
                counted += 1;
                if counted % 100 == 0 {
                    println!("errors {} / requests {}", errs, counted);
                    println!("{:?}", &strings);
                }
                if let Err(er) = rx {
                    errs += 1;
                    let st = format!("{:?}", er.source());
                    strings.insert(st);
                }
            }
            println!("errors {} / requests {}", errs, counted);
        }
        Commands::Completions => {
            let mut cmd = Cli::command();
            generate(Nushell, &mut cmd, "tuncurl", &mut io::stdout());
        }
    }

    Ok(())
}
