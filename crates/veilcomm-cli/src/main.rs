//! VeilComm CLI - Command-line interface for secure P2P messaging

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};

use veilcomm_app::VeilCommClient;

/// VeilComm - Secure P2P Encrypted Chat
#[derive(Parser)]
#[command(name = "veilcomm")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Data directory path
    #[arg(long, env = "VEILCOMM_DATA_DIR")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new identity
    Init {
        /// Your display name
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Show your identity information
    Identity,

    /// Manage contacts
    Contact {
        #[command(subcommand)]
        command: ContactCommands,
    },

    /// Send a message to a contact
    Send {
        /// Contact fingerprint or name
        contact: String,
        /// Message text
        message: String,
    },

    /// Read messages from a contact
    Read {
        /// Contact fingerprint or name
        contact: String,
        /// Number of messages to show
        #[arg(short, long, default_value = "20")]
        limit: u32,
    },

    /// Export your key bundle for sharing
    Export,

    /// Change your password
    ChangePassword,
}

#[derive(Subcommand)]
enum ContactCommands {
    /// Add a new contact
    Add {
        /// Contact fingerprint
        fingerprint: String,
        /// Contact name
        #[arg(short, long)]
        name: Option<String>,
    },

    /// List all contacts
    List,

    /// Remove a contact
    Remove {
        /// Contact fingerprint or name
        contact: String,
    },

    /// Verify a contact's identity
    Verify {
        /// Contact fingerprint or name
        contact: String,
    },
}

fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .init();

    let cli = Cli::parse();

    // Determine data directory
    let data_dir = cli.data_dir.unwrap_or_else(|| {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("veilcomm")
    });

    let mut client = VeilCommClient::new(&data_dir);

    match cli.command {
        Commands::Init { name } => cmd_init(&mut client, name.as_deref())?,
        Commands::Identity => cmd_identity(&mut client)?,
        Commands::Contact { command } => match command {
            ContactCommands::Add { fingerprint, name } => {
                cmd_contact_add(&mut client, &fingerprint, name.as_deref())?
            }
            ContactCommands::List => cmd_contact_list(&mut client)?,
            ContactCommands::Remove { contact } => cmd_contact_remove(&mut client, &contact)?,
            ContactCommands::Verify { contact } => cmd_contact_verify(&mut client, &contact)?,
        },
        Commands::Send { contact, message } => cmd_send(&mut client, &contact, &message)?,
        Commands::Read { contact, limit } => cmd_read(&mut client, &contact, limit)?,
        Commands::Export => cmd_export(&mut client)?,
        Commands::ChangePassword => cmd_change_password(&mut client)?,
    }

    Ok(())
}

fn prompt_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let password = rpassword::read_password()?;
    Ok(password)
}

fn unlock_client(client: &mut VeilCommClient) -> Result<()> {
    if !client.is_initialized() {
        anyhow::bail!("Not initialized. Run 'veilcomm init' first.");
    }

    let password = prompt_password("Password: ")?;
    client
        .unlock(&password)
        .context("Failed to unlock. Wrong password?")?;

    Ok(())
}

fn cmd_init(client: &mut VeilCommClient, name: Option<&str>) -> Result<()> {
    if client.is_initialized() {
        anyhow::bail!("Already initialized. Use a different data directory or delete the existing one.");
    }

    println!("Creating new VeilComm identity...\n");

    let password = prompt_password("Enter password: ")?;
    let password_confirm = prompt_password("Confirm password: ")?;

    if password != password_confirm {
        anyhow::bail!("Passwords don't match.");
    }

    if password.len() < 8 {
        anyhow::bail!("Password must be at least 8 characters.");
    }

    let fingerprint = client.init(&password, name)?;

    println!("\n✓ Identity created successfully!\n");
    println!("Your fingerprint: {}", fingerprint);

    if let Some(name) = name {
        println!("Display name: {}", name);
    }

    println!("\nShare your fingerprint with others to let them add you as a contact.");
    println!("Keep your password safe - it cannot be recovered!");

    Ok(())
}

fn cmd_identity(client: &mut VeilCommClient) -> Result<()> {
    unlock_client(client)?;

    let fingerprint = client.fingerprint()?;
    let name = client.name()?;

    println!("Identity Information");
    println!("====================");
    println!("Fingerprint: {}", fingerprint);

    if let Some(name) = name {
        println!("Name: {}", name);
    }

    // Show key bundle info
    let bundle = client.get_key_bundle()?;
    println!("\nKey Bundle:");
    println!("  Signed Pre-Key ID: {}", bundle.signed_prekey.id);
    println!("  One-Time Pre-Keys: {}", bundle.one_time_prekeys.len());

    Ok(())
}

fn cmd_contact_add(
    client: &mut VeilCommClient,
    fingerprint: &str,
    name: Option<&str>,
) -> Result<()> {
    unlock_client(client)?;

    // For now, we need the full key bundle to add a contact
    // In a real implementation, this would come from the network
    println!("Note: Full contact addition requires receiving their key bundle.");
    println!("This is a placeholder - in the future, use 'veilcomm connect <fingerprint>'");

    println!("\nContact fingerprint: {}", fingerprint);
    if let Some(name) = name {
        println!("Name: {}", name);
    }

    Ok(())
}

fn cmd_contact_list(client: &mut VeilCommClient) -> Result<()> {
    unlock_client(client)?;

    let contacts = client.list_contacts()?;

    if contacts.is_empty() {
        println!("No contacts yet. Add contacts with 'veilcomm contact add <fingerprint>'");
        return Ok(());
    }

    println!("Contacts");
    println!("========");

    for contact in contacts {
        let name = contact.name.as_deref().unwrap_or("<unnamed>");
        let verified = if contact.verified { "✓" } else { " " };
        let unread = client.unread_count(&contact.fingerprint)?;
        let unread_str = if unread > 0 {
            format!(" ({} unread)", unread)
        } else {
            String::new()
        };

        println!(
            "[{}] {} - {}{}",
            verified, name, &contact.fingerprint[..16], unread_str
        );
    }

    Ok(())
}

fn cmd_contact_remove(client: &mut VeilCommClient, contact: &str) -> Result<()> {
    unlock_client(client)?;

    // Try to find contact by name or fingerprint
    let contacts = client.list_contacts()?;
    let found = contacts.iter().find(|c| {
        c.fingerprint.starts_with(contact)
            || c.name.as_ref().map(|n| n == contact).unwrap_or(false)
    });

    if let Some(contact) = found {
        client.remove_contact(&contact.fingerprint)?;
        println!("✓ Contact removed.");
    } else {
        anyhow::bail!("Contact not found: {}", contact);
    }

    Ok(())
}

fn cmd_contact_verify(client: &mut VeilCommClient, contact: &str) -> Result<()> {
    unlock_client(client)?;

    // Try to find contact
    let contacts = client.list_contacts()?;
    let found = contacts.iter().find(|c| {
        c.fingerprint.starts_with(contact)
            || c.name.as_ref().map(|n| n == contact).unwrap_or(false)
    });

    if let Some(contact_info) = found {
        println!("Verify contact: {}", contact_info.name.as_deref().unwrap_or("<unnamed>"));
        println!("Fingerprint: {}", contact_info.fingerprint);
        println!("\nCompare this fingerprint with your contact through a trusted channel.");
        print!("Mark as verified? [y/N] ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if input.trim().eq_ignore_ascii_case("y") {
            // Mark as verified in database
            client.verify_contact(&contact_info.fingerprint, true)?;
            println!("✓ Contact marked as verified.");
        } else {
            println!("Verification cancelled.");
        }
    } else {
        anyhow::bail!("Contact not found: {}", contact);
    }

    Ok(())
}

fn cmd_send(client: &mut VeilCommClient, contact: &str, message: &str) -> Result<()> {
    unlock_client(client)?;

    // Find contact
    let contacts = client.list_contacts()?;
    let found = contacts.iter().find(|c| {
        c.fingerprint.starts_with(contact)
            || c.name.as_ref().map(|n| n == contact).unwrap_or(false)
    });

    if let Some(contact_info) = found {
        // Check if we have a session
        if !client.has_session(&contact_info.fingerprint) {
            anyhow::bail!(
                "No active session with {}. Use 'veilcomm connect {}' first.",
                contact_info.name.as_deref().unwrap_or(&contact_info.fingerprint),
                &contact_info.fingerprint[..16]
            );
        }

        let _encrypted = client.send_message(&contact_info.fingerprint, message)?;
        println!("✓ Message sent.");

        // In a real implementation, this would be sent over the network
        println!("(Note: Network transport not yet implemented)");
    } else {
        anyhow::bail!("Contact not found: {}", contact);
    }

    Ok(())
}

fn cmd_read(client: &mut VeilCommClient, contact: &str, limit: u32) -> Result<()> {
    unlock_client(client)?;

    // Find contact
    let contacts = client.list_contacts()?;
    let found = contacts.iter().find(|c| {
        c.fingerprint.starts_with(contact)
            || c.name.as_ref().map(|n| n == contact).unwrap_or(false)
    });

    if let Some(contact_info) = found {
        let messages = client.get_messages(&contact_info.fingerprint, limit)?;

        if messages.is_empty() {
            println!("No messages with {}.", contact_info.name.as_deref().unwrap_or(&contact_info.fingerprint));
            return Ok(());
        }

        let name = contact_info.name.as_deref().unwrap_or(&contact_info.fingerprint[..16]);
        println!("Messages with {}", name);
        println!("{}", "=".repeat(40));

        // Messages are returned newest first, reverse for display
        for msg in messages.iter().rev() {
            let direction = if msg.outgoing { "→" } else { "←" };
            let time = msg.timestamp.format("%Y-%m-%d %H:%M");
            let content = String::from_utf8_lossy(&msg.content);
            let read_marker = if !msg.outgoing && !msg.read { " •" } else { "" };

            println!("[{}] {} {}{}", time, direction, content, read_marker);
        }

        // Mark as read
        client.mark_read(&contact_info.fingerprint)?;
    } else {
        anyhow::bail!("Contact not found: {}", contact);
    }

    Ok(())
}

fn cmd_export(client: &mut VeilCommClient) -> Result<()> {
    unlock_client(client)?;

    let bundle = client.get_key_bundle()?;

    println!("Your Key Bundle");
    println!("===============");
    println!("Share this with others to let them message you.\n");

    // Serialize to base64 for easy sharing
    let bundle_bytes = bincode::serialize(&bundle)?;
    let bundle_base64 = base64::engine::general_purpose::STANDARD.encode(&bundle_bytes);

    println!("Fingerprint: {}", bundle.identity.fingerprint());
    println!("\nKey Bundle (base64):");
    println!("{}", bundle_base64);

    Ok(())
}

fn cmd_change_password(client: &mut VeilCommClient) -> Result<()> {
    if !client.is_initialized() {
        anyhow::bail!("Not initialized.");
    }

    let old_password = prompt_password("Current password: ")?;
    let new_password = prompt_password("New password: ")?;
    let new_password_confirm = prompt_password("Confirm new password: ")?;

    if new_password != new_password_confirm {
        anyhow::bail!("New passwords don't match.");
    }

    if new_password.len() < 8 {
        anyhow::bail!("Password must be at least 8 characters.");
    }

    // Determine keystore path
    let data_dir = client.data_dir();
    let keystore_path = data_dir.join("keystore.bin");

    // Load keystore from file
    let keystore_bytes = std::fs::read(&keystore_path)
        .context("Failed to read keystore file")?;
    let mut keystore = veilcomm_storage::keystore::KeyStore::from_bytes(&keystore_bytes)
        .context("Failed to parse keystore")?;

    // Change password (verifies old password, re-encrypts all keys)
    keystore.change_password(&old_password, &new_password)
        .context("Failed to change password. Wrong current password?")?;

    // Write updated keystore back to file
    let new_bytes = keystore.to_bytes()
        .context("Failed to serialize keystore")?;
    std::fs::write(&keystore_path, new_bytes)
        .context("Failed to write updated keystore")?;

    println!("✓ Password changed successfully.");

    Ok(())
}
