mod config;
mod identity;
mod ledger;
mod mcp;
mod policy;
mod proxy;
mod report;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "estoppl", version, about = "Compliance proxy for AI agent tool calls")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new estoppl config, keypair, and database in the current directory.
    Init {
        /// Agent identifier (e.g. "treasury-bot-v2").
        #[arg(long, default_value = "my-agent")]
        agent_id: String,
    },

    /// Start the stdio proxy — intercepts MCP tool calls between agent and upstream server.
    Start {
        /// Command to launch the upstream MCP server.
        #[arg(long)]
        upstream_cmd: String,

        /// Arguments to pass to the upstream command.
        #[arg(long, num_args = 0..)]
        upstream_args: Vec<String>,

        /// Path to estoppl config file.
        #[arg(long, short, default_value = "estoppl.toml")]
        config: PathBuf,
    },

    /// Generate a local compliance report (HTML) from logged events.
    Report {
        /// Output file path.
        #[arg(long, short, default_value = "estoppl-report.html")]
        output: PathBuf,

        /// Path to estoppl config file (for database location).
        #[arg(long, short, default_value = "estoppl.toml")]
        config: PathBuf,
    },

    /// View and verify the local audit log.
    Audit {
        /// Number of recent events to show.
        #[arg(long, short = 'n', default_value = "20")]
        limit: u32,

        /// Verify hash chain integrity.
        #[arg(long)]
        verify: bool,

        /// Path to estoppl config file.
        #[arg(long, short, default_value = "estoppl.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { agent_id } => cmd_init(&agent_id)?,
        Commands::Start {
            upstream_cmd,
            upstream_args,
            config,
        } => cmd_start(&upstream_cmd, &upstream_args, &config).await?,
        Commands::Report { output, config } => cmd_report(&output, &config)?,
        Commands::Audit {
            limit,
            verify,
            config,
        } => cmd_audit(limit, verify, &config)?,
    }

    Ok(())
}

fn cmd_init(agent_id: &str) -> Result<()> {
    let config = config::ProxyConfig::generate_default(agent_id);
    let config_path = PathBuf::from("estoppl.toml");

    if config_path.exists() {
        anyhow::bail!("estoppl.toml already exists. Remove it first to reinitialize.");
    }

    // Write config.
    let toml_str = config.to_toml()?;
    std::fs::write(&config_path, &toml_str)?;
    println!("Created estoppl.toml");

    // Generate keypair.
    let key_dir = PathBuf::from(".estoppl/keys");
    let km = identity::KeyManager::load_or_generate(&key_dir)?;
    println!("Generated Ed25519 keypair (key_id: {})", km.key_id);

    // Initialize database.
    let db_path = config.ledger.db_path;
    let _ledger = ledger::LocalLedger::open(&db_path)?;
    println!("Initialized database at {}", db_path.display());

    println!();
    println!("Ready. Start the proxy with:");
    println!("  estoppl start --upstream-cmd <your-mcp-server-command>");
    Ok(())
}

async fn cmd_start(
    upstream_cmd: &str,
    upstream_args: &[String],
    config_path: &PathBuf,
) -> Result<()> {
    let config = config::ProxyConfig::load(config_path)?;
    let key_dir = PathBuf::from(".estoppl/keys");
    let key_manager = identity::KeyManager::load_or_generate(&key_dir)?;
    let db_ledger = ledger::LocalLedger::open(&config.ledger.db_path)?;
    let policy_engine = policy::PolicyEngine::new(config.rules.clone());

    tracing::info!(
        agent_id = config.agent.id,
        key_id = key_manager.key_id,
        "Estoppl proxy starting"
    );

    proxy::run_stdio_proxy(
        upstream_cmd,
        upstream_args,
        &config.agent.id,
        &config.agent.version,
        config.agent.authorized_by.as_deref().unwrap_or("unknown"),
        &key_manager,
        &db_ledger,
        &policy_engine,
    )
    .await
}

fn cmd_report(output: &PathBuf, config_path: &PathBuf) -> Result<()> {
    let config = config::ProxyConfig::load(config_path)?;
    let db_ledger = ledger::LocalLedger::open(&config.ledger.db_path)?;

    let html = report::generate_html_report(&db_ledger)?;
    std::fs::write(output, &html)
        .with_context(|| format!("Failed to write report to {}", output.display()))?;

    println!("Report written to {}", output.display());
    Ok(())
}

fn cmd_audit(limit: u32, verify: bool, config_path: &PathBuf) -> Result<()> {
    let config = config::ProxyConfig::load(config_path)?;
    let db_ledger = ledger::LocalLedger::open(&config.ledger.db_path)?;

    if verify {
        let (total, broken) = db_ledger.verify_chain()?;
        if broken.is_empty() {
            println!("Hash chain INTACT — {} events verified", total);
        } else {
            println!(
                "Hash chain BROKEN — {} events, {} issues:",
                total,
                broken.len()
            );
            for issue in &broken {
                println!("  - {}", issue);
            }
        }
        return Ok(());
    }

    let events = db_ledger.query_events(Some(limit), None)?;

    if events.is_empty() {
        println!("No events recorded yet.");
        return Ok(());
    }

    println!(
        "{:<10} {:<30} {:<12} {:<22} {}",
        "EVENT", "TOOL", "DECISION", "TIMESTAMP", "LATENCY"
    );
    println!("{}", "-".repeat(90));

    for e in &events {
        println!(
            "{:<10} {:<30} {:<12} {:<22} {}ms",
            &e.event_id[..8],
            truncate(&e.tool_name, 28),
            e.policy_decision,
            e.timestamp.format("%Y-%m-%d %H:%M:%S"),
            e.latency_ms,
        );
    }

    let stats = db_ledger.summary_stats()?;
    println!();
    println!(
        "Total: {} | Allowed: {} | Blocked: {} | Human Review: {}",
        stats.total_events, stats.allowed, stats.blocked, stats.human_required
    );

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max - 3])
    } else {
        s.to_string()
    }
}
