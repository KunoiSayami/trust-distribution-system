use std::path::PathBuf;

use anyhow::Context;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use clap::{Parser, Subcommand};
use pub_impl::ParsedToken;
use serde::{Deserialize, Serialize};

mod actions;
mod config;
mod sync;

use config::ClientConfig;
use sync::{SyncState, TdsClient};

#[derive(Parser)]
#[command(name = "tds-client")]
#[command(about = "Trust Distribution System - Client")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Configuration file path
    #[arg(short, long, default_value = "client.toml")]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the client (poll and sync)
    Run {
        /// Run once and exit (don't poll)
        #[arg(long)]
        once: bool,
    },
    /// Generate client keys
    Keygen {
        /// Output directory for keys
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },
    /// Sync now (one-time sync)
    Sync,
    /// Enroll with a server using a token
    Enroll {
        /// Server URL (e.g., https://server:8443)
        #[arg(long)]
        server: String,
        /// Enrollment token from server admin
        #[arg(long)]
        token: String,
        /// Output directory for config and keys
        #[arg(long, default_value = ".")]
        config_dir: PathBuf,
    },
}

async fn run_client(config_path: PathBuf, once: bool) -> anyhow::Result<()> {
    log::info!("Loading configuration from {:?}", config_path);
    let config = ClientConfig::load(&config_path)?;

    log::info!("Loading client keys...");
    let signing_key =
        encryption::async_fn::load_signing_key(&config.client.keys.signing_key_path).await?;
    let age_identity =
        encryption::async_fn::load_age_identity(&config.client.keys.age_identity_path).await?;

    // Parse server verify key
    let server_key_bytes = BASE64
        .decode(&config.client.keys.server_verify_key)
        .context("Invalid server verify key encoding")?;
    let server_key_array: [u8; 32] = server_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Server verify key must be 32 bytes"))?;
    let server_verify_key = encryption::VerifyingKey::from_bytes(&server_key_array)?;

    // Create HTTP client
    let client = TdsClient::new(
        config.client.server_url.clone(),
        config.client.id.clone(),
        signing_key,
        server_verify_key,
        age_identity,
    )?;

    // Load or create state
    let mut state = SyncState::load(&config.client.state_file).unwrap_or_default();

    // Get subscribed groups
    let subscribed_groups: Vec<String> = config.subscriptions.keys().cloned().collect();

    if once {
        sync_once(&client, &config, &mut state, &subscribed_groups).await?;
    } else {
        // Polling loop
        let poll_interval = std::time::Duration::from_secs(config.client.poll_interval);
        log::info!(
            "Starting polling loop (interval: {}s)",
            config.client.poll_interval
        );

        loop {
            if let Err(e) = sync_once(&client, &config, &mut state, &subscribed_groups).await {
                log::error!("Sync failed: {}", e);
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    Ok(())
}

async fn sync_once(
    client: &TdsClient,
    config: &ClientConfig,
    state: &mut SyncState,
    subscribed_groups: &[String],
) -> anyhow::Result<()> {
    log::info!("Fetching manifest...");
    let manifest = client.fetch_manifest().await?;
    log::debug!("Manifest has {} files", manifest.files.len());

    // Determine which files need downloading
    let to_download = sync::files_to_download(&manifest, state, subscribed_groups);

    if to_download.is_empty() {
        log::info!("All files up to date");
        return Ok(());
    }

    log::info!("{} file(s) need updating", to_download.len());

    let mut downloaded_files = Vec::new();

    for file in &to_download {
        log::info!("Downloading: {}", file.path);

        match client.download_file(&file.path).await {
            Ok(content) => {
                // Determine output path
                let output_path = match sync::get_output_path(file, config) {
                    Some(p) => p,
                    None => {
                        log::warn!(
                            "No subscription for group {}, skipping {}",
                            file.group,
                            file.path
                        );
                        continue;
                    }
                };

                // Create parent directories
                if let Some(parent) = output_path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }

                // Write file
                tokio::fs::write(&output_path, &content).await?;
                log::info!("Wrote {} ({} bytes)", output_path.display(), content.len());

                // Update state
                state
                    .file_hashes
                    .insert(file.path.clone(), file.content_hash.clone());
                downloaded_files.push(file.clone());
            }
            Err(e) => {
                log::error!("Failed to download {}: {}", file.path, e);
            }
        }
    }

    // Save state
    state.last_sync = Some(chrono::Utc::now().timestamp_millis());
    state.save(&config.client.state_file)?;

    // Execute actions for changed files
    if !downloaded_files.is_empty() {
        log::info!("Executing post-download actions...");
        if let Err(e) = actions::execute_actions(&downloaded_files, config) {
            log::error!("Action execution failed: {}", e);
        }
    }

    Ok(())
}

async fn generate_keys(output: PathBuf) -> anyhow::Result<()> {
    log::info!("Generating client keys in {:?}", output);

    // Create output directory if needed
    tokio::fs::create_dir_all(&output).await?;

    // Generate Ed25519 signing key
    let signing_key = encryption::SigningKey::generate();
    let signing_key_path = output.join("client_signing.key");
    let verifying_key_path = output.join("client_signing.pub");

    encryption::async_fn::write_signing_key(&signing_key_path, &signing_key).await?;
    encryption::async_fn::write_verifying_key(&verifying_key_path, &signing_key.verifying_key())
        .await?;

    log::info!("Wrote signing key to {:?}", signing_key_path);
    log::info!("Wrote verifying key to {:?}", verifying_key_path);

    // Generate age identity
    let age_identity = encryption::AgeIdentity::generate();
    let age_identity_path = output.join("client.age");

    encryption::async_fn::write_age_identity(&age_identity_path, &age_identity).await?;

    log::info!("Wrote age identity to {:?}", age_identity_path);

    // Print public keys for server registration
    println!("\nClient keys generated successfully!");
    println!("Signing key: {:?}", signing_key_path);
    println!("Age identity: {:?}", age_identity_path);
    println!("\n--- Add to server config ---");
    println!(
        "age_public_key = \"{}\"",
        age_identity.to_recipient().to_string()
    );
    println!(
        "auth_public_key = \"{}\"",
        BASE64.encode(signing_key.verifying_key().to_bytes())
    );

    Ok(())
}

#[derive(Serialize)]
struct EnrollRequest {
    token_secret: String,
    encrypted_payload: String,
}

#[derive(Serialize)]
struct EnrollPayload {
    age_public_key: String,
    auth_public_key: String,
}

#[derive(Deserialize)]
struct EnrollResponse {
    client_id: String,
    groups: Vec<String>,
}

async fn enroll(server: String, token: String, config_dir: PathBuf) -> anyhow::Result<()> {
    println!("Parsing enrollment token...");
    let parsed = ParsedToken::parse(&token)?;

    // Create output directory
    tokio::fs::create_dir_all(&config_dir).await?;

    println!("Generating keypairs...");

    // Generate Ed25519 signing key
    let signing_key = encryption::SigningKey::generate();
    let signing_key_path = config_dir.join("client_signing.key");
    encryption::async_fn::write_signing_key(&signing_key_path, &signing_key).await?;

    // Generate age identity
    let age_identity = encryption::AgeIdentity::generate();
    let age_identity_path = config_dir.join("client.age");
    encryption::async_fn::write_age_identity(&age_identity_path, &age_identity).await?;

    // Prepare enrollment payload
    let payload = EnrollPayload {
        age_public_key: age_identity.to_recipient().to_string(),
        auth_public_key: BASE64.encode(signing_key.verifying_key().to_bytes()),
    };

    let payload_json = serde_json::to_vec(&payload)?;

    // Encrypt payload with server's age public key
    let server_recipient = encryption::AgeRecipient::from_str(&parsed.server_age_recipient)?;
    let encrypted = encryption::encrypt(&server_recipient, payload_json)?;
    let encrypted_b64 = BASE64.encode(encrypted.into_inner());

    println!("Enrolling with server...");

    // Send enrollment request
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/api/v1/enroll", server))
        .json(&EnrollRequest {
            token_secret: parsed.secret,
            encrypted_payload: encrypted_b64,
        })
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Enrollment failed: {} - {}", status, body);
    }

    let enroll_response: EnrollResponse = response.json().await?;

    println!("✓ Enrolled as \"{}\"", enroll_response.client_id);
    println!("✓ Allowed groups: {}", enroll_response.groups.join(", "));

    // Write client config
    let config_path = config_dir.join("client.toml");
    let config_content = format!(
        r#"version = 1

[client]
id = "{}"
server_url = "{}"
poll_interval = 300
state_file = "{}"

[client.keys]
age_identity_path = "{}"
signing_key_path = "{}"
server_verify_key = "{}"

# TODO: Configure your subscriptions
# [subscriptions.groupname]
# output_directory = "/path/to/output"
# preserve_structure = true
#
# [actions.groups.groupname]
# command = "/path/to/script"
# args = []
# on_change_only = true
"#,
        enroll_response.client_id,
        server,
        config_dir.join("state.json").display(),
        age_identity_path.display(),
        signing_key_path.display(),
        parsed.server_verify_key,
    );

    tokio::fs::write(&config_path, config_content).await?;

    println!("✓ Config written to {}", config_path.display());
    println!("✓ Keys written to {}", config_dir.display());
    println!("\nNext steps:");
    println!(
        "1. Edit {} to configure subscriptions",
        config_path.display()
    );
    println!("2. Run: client -c {} run", config_path.display());

    Ok(())
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Some(Commands::Run { once }) => run_client(cli.config, once).await,
        Some(Commands::Keygen { output }) => generate_keys(output).await,
        Some(Commands::Sync) => run_client(cli.config, true).await,
        Some(Commands::Enroll {
            server,
            token,
            config_dir,
        }) => enroll(server, token, config_dir).await,
        None => run_client(cli.config, false).await,
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
