use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cgka_traits::GroupId;
use marmot_lab::{Lab, SyncSummary};

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = parse_args()?;
    let lab = lab_for(cli.home, cli.relay_url);
    match cli.args.first().map(String::as_str) {
        Some("relay") if cli.args.len() == 1 => {
            run_relay().await?;
        }
        Some("init") if cli.args.len() == 2 => {
            let label = &cli.args[1];
            let account_id = lab.init_account(label).await?;
            println!("initialized {label} {}", hex::encode(account_id.as_slice()));
        }
        Some("status") if cli.args.len() == 2 => {
            let label = &cli.args[1];
            println!("{}", serde_json::to_string_pretty(&lab.status(label)?)?);
        }
        Some("smoke") if cli.args.len() == 1 => {
            run_smoke(&lab).await?;
        }
        Some("restart-smoke") if cli.args.len() == 1 => {
            run_restart_smoke(&lab).await?;
        }
        Some("mock-smoke") if cli.args.len() == 1 => {
            let relay = nostr_relay_builder::MockRelay::run().await?;
            let url = relay.url().await.to_string();
            println!("mock relay {url}");
            let lab = Lab::with_sdk_relay(unique_smoke_home(), url);
            run_smoke(&lab).await?;
        }
        Some("mock-restart-smoke") if cli.args.len() == 1 => {
            let relay = nostr_relay_builder::MockRelay::run().await?;
            let url = relay.url().await.to_string();
            println!("mock relay {url}");
            let lab = Lab::with_sdk_relay(unique_smoke_home(), url);
            run_restart_smoke(&lab).await?;
        }
        Some("client") if cli.args.len() == 2 => {
            let label = &cli.args[1];
            run_client(&lab, label).await?;
        }
        _ => {
            print_usage();
        }
    }
    Ok(())
}

struct CliArgs {
    home: PathBuf,
    relay_url: Option<String>,
    args: Vec<String>,
}

fn lab_for(home: PathBuf, relay_url: Option<String>) -> Lab {
    match relay_url {
        Some(url) => Lab::with_sdk_relay(home, url),
        None => Lab::new(home),
    }
}

fn unique_smoke_home() -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    std::env::temp_dir().join(format!("marmot-lab-mock-smoke-{millis}"))
}

async fn run_relay() -> Result<(), Box<dyn std::error::Error>> {
    let relay = nostr_relay_builder::MockRelay::run().await?;
    println!("{}", relay.url().await);
    println!("marmot-lab mock relay running; press Ctrl-C to stop");
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

async fn run_smoke(lab: &Lab) -> Result<(), Box<dyn std::error::Error>> {
    lab.init_account("alice").await?;
    lab.init_account("bob").await?;
    let mut alice = lab.client("alice").await?;
    let mut bob = lab.client("bob").await?;
    bob.publish_key_package().await?;
    let group_id = alice.create_group("smoke", &["bob"]).await?;
    print_sync("bob", bob.sync().await?);
    alice
        .send(&group_id, b"hello from marmot-lab smoke")
        .await?;
    print_sync("bob", bob.sync().await?);
    println!("smoke ok group={}", hex::encode(group_id.as_slice()));
    Ok(())
}

async fn run_restart_smoke(lab: &Lab) -> Result<(), Box<dyn std::error::Error>> {
    let summary = lab.restart_smoke().await?;
    println!(
        "restart smoke ok group={} messages={}",
        hex::encode(summary.group_id.as_slice()),
        summary.messages.len()
    );
    Ok(())
}

async fn run_client(lab: &Lab, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    lab.init_account(label).await?;
    let mut client = lab.client(label).await?;
    println!("marmot-lab client {label}");
    println!("type 'help' for commands");

    loop {
        let mut line = String::new();
        print_prompt(label)?;
        if std::io::stdin().read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace().collect::<Vec<_>>();
        let command = parts.remove(0);
        match command {
            "help" => print_client_help(),
            "quit" | "exit" => break,
            "keypkg" | "kp" => {
                let kp = client.publish_key_package().await?;
                println!("published key package bytes={}", kp.0.len());
            }
            "create" => {
                if parts.len() < 2 {
                    println!("usage: create <name> <member-label> [member-label...]");
                    continue;
                }
                let name = parts.remove(0);
                let group = client.create_group(name, &parts).await?;
                println!("created group {}", hex::encode(group.as_slice()));
            }
            "send" => {
                if parts.len() < 2 {
                    println!("usage: send <group-hex> <message...>");
                    continue;
                }
                let group = group_from_hex(parts.remove(0))?;
                let message = parts.join(" ");
                let sent = client.send(&group, message.as_bytes()).await?;
                println!("published {} transport message(s)", sent.published);
            }
            "sync" => {
                print_sync(label, client.sync().await?);
            }
            "tail" => {
                let poll_ms = parts
                    .first()
                    .map(|value| value.parse::<u64>())
                    .transpose()?
                    .unwrap_or(500);
                println!("tailing {label}; press Ctrl-C to stop");
                loop {
                    print_sync(label, client.sync().await?);
                    tokio::time::sleep(Duration::from_millis(poll_ms)).await;
                }
            }
            "status" => {
                println!("{}", serde_json::to_string_pretty(&lab.status(label)?)?);
            }
            other => {
                println!("unknown command: {other}");
            }
        }
    }
    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut home = std::env::var_os("MARMOT_LAB_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".marmot-lab"));
    let mut relay_url = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--home" => {
                if i + 1 >= args.len() {
                    return Err("--home requires a path".into());
                }
                home = PathBuf::from(args.remove(i + 1));
                args.remove(i);
            }
            "--relay" => {
                if i + 1 >= args.len() {
                    return Err("--relay requires a ws:// or wss:// relay URL".into());
                }
                relay_url = Some(args.remove(i + 1));
                args.remove(i);
            }
            _ => i += 1,
        }
    }
    Ok(CliArgs {
        home,
        relay_url,
        args,
    })
}

fn print_usage() {
    eprintln!(
        "usage:
  marmot-lab relay
  marmot-lab [--home PATH] [--relay URL] mock-smoke
  marmot-lab [--home PATH] [--relay URL] mock-restart-smoke
  marmot-lab [--home PATH] init <label>
  marmot-lab [--home PATH] status <label>
  marmot-lab [--home PATH] [--relay URL] client <label>
  marmot-lab [--home PATH] [--relay URL] smoke
  marmot-lab [--home PATH] [--relay URL] restart-smoke"
    );
}

fn print_client_help() {
    println!(
        "commands:
  keypkg | kp                         publish this client's latest key package
  create <name> <member> [...]        create a group and invite members
  sync                                poll relay deliveries and ingest messages
  send <group-hex> <message...>       send an app message to a group
  tail [poll-ms]                      keep syncing until Ctrl-C
  status                              print local lab state
  quit                                exit"
    );
}

fn print_sync(label: &str, summary: SyncSummary) {
    for group in summary.joined_groups {
        println!("{label} joined group {}", hex::encode(group.as_slice()));
    }
    for (sender, group, message) in summary.messages {
        println!(
            "{label} received group={} from={sender}: {message}",
            hex::encode(group.as_slice())
        );
    }
    if summary.events.is_empty() {
        println!("{label} sync: no new events");
    }
}

fn group_from_hex(value: &str) -> Result<GroupId, hex::FromHexError> {
    Ok(GroupId::new(hex::decode(value)?))
}

fn print_prompt(label: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    print!("{label}> ");
    std::io::stdout().flush()
}
