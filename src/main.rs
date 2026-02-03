use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod admin;
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
    /// Token management (via HTTP to running server)
    Token {
        #[command(subcommand)]
        action: TokenAction,

        /// Server config file (to auto-read TOTP secret and bind address)
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,

        /// Server URL (overrides config bind address)
        #[arg(long, short = 's', default_value = "http://127.0.0.1:8080")]
        server: String,

        /// Admin password
        #[arg(long, short = 'p')]
        password: String,

        /// TOTP code (auto-generated if --config provided with admin section)
        #[arg(long, short = 't')]
        totp: Option<String>,
    },
    /// Generate current TOTP code from a secret
    Totp {
        /// Base32-encoded TOTP secret
        secret: String,
    },
    /// Generate Argon2id password hash for config
    HashPassword {
        /// Password to hash
        password: String,
    },
    /// Generate new TOTP secret for initial setup
    TotpSetup {
        /// Account name for authenticator app
        #[arg(long)]
        account: String,
        /// Issuer name for authenticator app
        #[arg(long, default_value = "TDS")]
        issuer: String,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    /// Generate new enrollment token(s)
    New {
        /// Client ID for the new client
        #[arg(long)]
        client_id: String,
        /// Comma-separated list of groups
        #[arg(long, value_delimiter = ',')]
        groups: Vec<String>,
        /// Number of tokens to generate
        #[arg(long, default_value = "1")]
        count: u32,
        /// Token expiry in hours
        #[arg(long)]
        expiry: Option<u32>,
    },
    /// List pending tokens
    List,
    /// Revoke tokens by client ID
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

    // Create empty in-memory token store
    let token_store = TokenStore::new();

    let state = AppState::new(
        config.clone(),
        signing_key,
        age_identity,
        token_store,
        config_path,
    );

    // Start cleanup task for nonce cache and token store
    let nonce_cache = state.nonce_cache.clone();
    let token_store_cleanup = state.token_store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            nonce_cache.cleanup();
            token_store_cleanup.write().await.cleanup();
        }
    });

    if config.server.admin.is_some() {
        log::info!("Admin endpoint enabled at /api/v1/admin/tokens");
    } else {
        log::warn!("Admin endpoint disabled (no [server.admin] config)");
    }

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

/// Resolve server URL and TOTP code from arguments and/or config file
fn resolve_admin_credentials(
    config_path: &Option<PathBuf>,
    server_arg: &str,
    totp_arg: &Option<String>,
) -> anyhow::Result<(String, String)> {
    // If config provided, try to read TOTP secret and bind address
    let (server_url, totp_code) = if let Some(cfg_path) = config_path {
        let config = ServerConfig::load(cfg_path)?;

        // Get server URL from config bind address
        let server_url = format!("http://{}", config.server.bind);

        // Get TOTP code - either from arg or generate from config secret
        let totp_code = match totp_arg {
            Some(code) => code.clone(),
            None => {
                let admin_config = config.server.admin.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("No [server.admin] section in config; provide --totp manually")
                })?;
                admin::generate_totp_code(&admin_config.totp_secret)?
            }
        };

        (server_url, totp_code)
    } else {
        // No config - use server arg and require TOTP arg
        let totp_code = totp_arg
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Either --config or --totp must be provided"))?;
        (server_arg.to_string(), totp_code)
    };

    Ok((server_url, totp_code))
}

async fn token_command(
    action: TokenAction,
    config_path: Option<PathBuf>,
    server_arg: String,
    password: String,
    totp_arg: Option<String>,
) -> anyhow::Result<()> {
    let (server_url, totp_code) = resolve_admin_credentials(&config_path, &server_arg, &totp_arg)?;

    let client = reqwest::Client::new();

    match action {
        TokenAction::New {
            client_id,
            groups,
            count,
            expiry,
        } => {
            let mut body = serde_json::json!({
                "client_id": client_id,
                "groups": groups,
                "count": count,
            });
            if let Some(exp) = expiry {
                body["expiry_hours"] = serde_json::json!(exp);
            }

            let response = client
                .post(format!("{}/api/v1/admin/tokens", server_url))
                .header("Authorization", format!("Admin {}", password))
                .header("X-TOTP-Code", &totp_code)
                .json(&body)
                .send()
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Created {} token(s):\n", result["count"]);
                if let Some(tokens) = result["tokens"].as_array() {
                    for token_info in tokens {
                        println!("Client ID: {}", token_info["client_id"]);
                        println!("Groups: {:?}", token_info["groups"]);
                        println!("Expires: {}", token_info["expires_at"]);
                        println!("Token:\n  {}\n", token_info["token"].as_str().unwrap_or(""));
                    }
                }
            } else {
                let error: serde_json::Value = response.json().await?;
                anyhow::bail!("Failed to create token: {}", error["error"]);
            }
        }
        TokenAction::List => {
            let response = client
                .get(format!("{}/api/v1/admin/tokens", server_url))
                .header("Authorization", format!("Admin {}", password))
                .header("X-TOTP-Code", &totp_code)
                .send()
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let count = result["count"].as_u64().unwrap_or(0);
                if count == 0 {
                    println!("No pending tokens.");
                } else {
                    println!("{:<20} {:<30} {:<25}", "CLIENT-ID", "GROUPS", "EXPIRES");
                    println!("{}", "-".repeat(75));
                    if let Some(tokens) = result["tokens"].as_array() {
                        for entry in tokens {
                            let groups = entry["groups"]
                                .as_array()
                                .map(|g| {
                                    g.iter()
                                        .filter_map(|v| v.as_str())
                                        .collect::<Vec<_>>()
                                        .join(",")
                                })
                                .unwrap_or_default();
                            println!(
                                "{:<20} {:<30} {:<25}",
                                entry["client_id"].as_str().unwrap_or(""),
                                groups,
                                entry["expires_at"].as_str().unwrap_or("")
                            );
                        }
                    }
                }
            } else {
                let error: serde_json::Value = response.json().await?;
                anyhow::bail!("Failed to list tokens: {}", error["error"]);
            }
        }
        TokenAction::Revoke { client_id } => {
            let response = client
                .delete(format!("{}/api/v1/admin/tokens/{}", server_url, client_id))
                .header("Authorization", format!("Admin {}", password))
                .header("X-TOTP-Code", &totp_code)
                .send()
                .await?;

            if response.status().is_success() {
                println!("Token(s) for '{}' revoked.", client_id);
            } else if response.status() == reqwest::StatusCode::NOT_FOUND {
                println!("No pending token found for '{}'.", client_id);
            } else {
                let error: serde_json::Value = response.json().await?;
                anyhow::bail!("Failed to revoke token: {}", error["error"]);
            }
        }
    }

    Ok(())
}

fn totp_command(secret: &str) -> anyhow::Result<()> {
    let code = admin::generate_totp_code(secret)?;
    println!("{}", code);
    Ok(())
}

fn hash_password_command(password: &str) -> anyhow::Result<()> {
    let hash = admin::hash_password(password)?;
    println!("{}", hash);
    Ok(())
}

fn totp_setup_command(account: &str, issuer: &str) -> anyhow::Result<()> {
    let secret = admin::generate_totp_secret();

    // Generate otpauth URL for QR code
    let otpauth_url = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        issuer, account, secret, issuer
    );

    println!("TOTP Setup for {}", account);
    println!("{}", "=".repeat(50));
    println!("\nSecret (for server.toml [server.admin] section):");
    println!("  totp_secret = \"{}\"", secret);
    println!("\nOTPAuth URL (for QR code generators):");
    println!("  {}", otpauth_url);
    println!("\nManual entry in authenticator app:");
    println!("  Account: {}:{}", issuer, account);
    println!("  Secret: {}", secret);
    println!("  Type: Time-based");
    println!("  Algorithm: SHA1");
    println!("  Digits: 6");
    println!("  Period: 30 seconds");

    Ok(())
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Some(Commands::Server) | None => run_server(cli.config).await,
        Some(Commands::Keygen { output }) => generate_keys(output).await,
        Some(Commands::Token {
            action,
            config,
            server,
            password,
            totp,
        }) => token_command(action, config, server, password, totp).await,
        Some(Commands::Totp { secret }) => totp_command(&secret),
        Some(Commands::HashPassword { password }) => hash_password_command(&password),
        Some(Commands::TotpSetup { account, issuer }) => totp_setup_command(&account, &issuer),
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
