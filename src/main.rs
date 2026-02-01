use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::{Parser, Subcommand};

mod configure;
mod enrollment;
mod types;
mod web;

use configure::ServerConfig;
use enrollment::TokenStore;
use types::AppState;

#[derive(Parser)]
#[command(name = "tds")]
#[command(about = "Trust Distribution System - Server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Configuration file path
    #[arg(short, long, default_value = "server.toml")]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the server
    Server,
    /// Generate server keys
    Keygen {
        /// Output directory for keys
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },
    /// Token management
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    /// Generate a new enrollment token
    New {
        /// Client ID for the new client
        #[arg(long)]
        client_id: String,
        /// Comma-separated list of groups
        #[arg(long)]
        groups: String,
        /// Token expiry in hours (default: 1)
        #[arg(long, default_value = "1")]
        expiry: u32,
    },
    /// List pending tokens
    List,
    /// Revoke a token by client ID
    Revoke {
        /// Client ID to revoke
        #[arg(long)]
        client_id: String,
    },
}

async fn run_server(config_path: PathBuf) -> anyhow::Result<()> {
    log::info!("Loading configuration from {:?}", config_path);
    let config = ServerConfig::load(&config_path)?;

    log::info!("Loading server keys...");
    let signing_key =
        encryption::async_fn::load_signing_key(&config.server.keys.signing_key_path).await?;
    let age_identity =
        encryption::async_fn::load_age_identity(&config.server.keys.age_identity_path).await?;

    log::info!(
        "Server age recipient: {}",
        age_identity.to_recipient().to_string()
    );

    // Load token store
    let token_store_path = config_path.parent().unwrap_or(std::path::Path::new(".")).join("tokens.json");
    let token_store = TokenStore::load(&token_store_path).unwrap_or_default();

    let state = AppState::new(config.clone(), signing_key, age_identity, token_store, token_store_path);

    // Start nonce cache cleanup task
    let nonce_cache = state.nonce_cache.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            nonce_cache.cleanup();
        }
    });

    web::run_server(state, &config.server.bind).await
}

async fn generate_keys(output: PathBuf) -> anyhow::Result<()> {
    log::info!("Generating server keys in {:?}", output);

    // Create output directory if needed
    tokio::fs::create_dir_all(&output).await?;

    // Generate Ed25519 signing key
    let signing_key = encryption::SigningKey::generate();
    let signing_key_path = output.join("server_signing.key");
    let verifying_key_path = output.join("server_signing.pub");

    encryption::async_fn::write_signing_key(&signing_key_path, &signing_key).await?;
    encryption::async_fn::write_verifying_key(&verifying_key_path, &signing_key.verifying_key())
        .await?;

    log::info!("Wrote signing key to {:?}", signing_key_path);
    log::info!("Wrote verifying key to {:?}", verifying_key_path);

    // Generate age identity
    let age_identity = encryption::AgeIdentity::generate();
    let age_identity_path = output.join("server.age");

    encryption::async_fn::write_age_identity(&age_identity_path, &age_identity).await?;

    log::info!("Wrote age identity to {:?}", age_identity_path);
    log::info!(
        "Server age recipient (share with clients): {}",
        age_identity.to_recipient().to_string()
    );

    println!("\nServer keys generated successfully!");
    println!("Signing key: {:?}", signing_key_path);
    println!("Age identity: {:?}", age_identity_path);
    println!(
        "\nAge recipient (for client config): {}",
        age_identity.to_recipient().to_string()
    );

    Ok(())
}

async fn token_command(action: TokenAction, config_path: PathBuf) -> anyhow::Result<()> {
    let config = ServerConfig::load(&config_path)?;
    let token_store_path = config_path.parent().unwrap_or(std::path::Path::new(".")).join("tokens.json");
    let mut token_store = TokenStore::load(&token_store_path).unwrap_or_default();

    // Load server keys for token generation
    let signing_key =
        encryption::async_fn::load_signing_key(&config.server.keys.signing_key_path).await?;
    let age_identity =
        encryption::async_fn::load_age_identity(&config.server.keys.age_identity_path).await?;

    match action {
        TokenAction::New { client_id, groups, expiry } => {
            let groups: Vec<String> = groups.split(',').map(|s| s.trim().to_string()).collect();

            let server_age_recipient = age_identity.to_recipient().to_string();
            let server_verify_key = BASE64.encode(signing_key.verifying_key().to_bytes());

            let (token, entry) = enrollment::generate_token(
                &client_id,
                &groups,
                &server_age_recipient,
                &server_verify_key,
                expiry,
            );

            token_store.add(entry);
            token_store.save(&token_store_path)?;

            println!("Enrollment token (expires in {} hour(s)):", expiry);
            println!("  {}", token);
            println!("\nClient ID: {}", client_id);
            println!("Groups: {}", groups.join(", "));
        }
        TokenAction::List => {
            let pending = token_store.pending();
            if pending.is_empty() {
                println!("No pending tokens.");
            } else {
                println!("{:<20} {:<30} {:<25}", "CLIENT-ID", "GROUPS", "EXPIRES");
                println!("{}", "-".repeat(75));
                for entry in pending {
                    println!(
                        "{:<20} {:<30} {:<25}",
                        entry.client_id,
                        entry.groups.join(","),
                        entry.expires_at
                    );
                }
            }
        }
        TokenAction::Revoke { client_id } => {
            if token_store.revoke(&client_id) {
                token_store.save(&token_store_path)?;
                println!("Token for '{}' revoked.", client_id);
            } else {
                println!("No pending token found for '{}'.", client_id);
            }
        }
    }

    Ok(())
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Some(Commands::Server) | None => run_server(cli.config).await,
        Some(Commands::Keygen { output }) => generate_keys(output).await,
        Some(Commands::Token { action }) => token_command(action, cli.config).await,
    }
}

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_default_env().init();

    let cli = Cli::parse();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main(cli))
}
