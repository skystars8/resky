use anyhow::{bail, Context, Result};
use argon2::{Argon2, Params};
use blake3::Hasher;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use rpassword::prompt_password;
use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
    path::Path,
};

const MAX_SIZE: u64 = 20 * 1024 * 1024 * 1024; // 20 GiB
const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

/// =====================================================================================
/// COMPILE-TIME TWEAKABLE CONTEXT
/// =====================================================================================
/// 
/// This constant allows you to create different "universes" of keys.
/// Changing this value will produce completely different deterministic keys
/// even when using the exact same password and size.
///
/// RECOMMENDED MAX LENGTH: 256 bytes (longer values are allowed but provide diminishing returns).
/// 
/// SAFETY: Changing this value **cannot weaken** the cryptographic strength of the keys.
/// It only provides additional domain separation. The security properties remain the same
/// regardless of what context you choose.
///
/// Best practice: Use a meaningful, unique string for different projects or purposes.
/// Example values:
///   - b"project-alpha-backups-2026"
///   - b"test-environment-keys"
///   - b"personal-archive-v3"
///
/// Default: b"default-keygen1-context"
const KEY_CONTEXT: &[u8] = b"default-keygen1-context";

#[derive(Parser, Debug)]
#[command(name = "keygen1", version, about = "Generate high-quality deterministic cryptographic key files from a password")]
struct Args {
    /// Size of the key in bytes (1 to 20 GiB)
    #[arg(value_name = "BYTES")]
    size: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.size == 0 {
        bail!("Size must be at least 1 byte.");
    }
    if args.size > MAX_SIZE {
        bail!("Maximum supported size is 20 GiB.");
    }

    let path = Path::new("key.key");
    if path.exists() {
        bail!("key.key already exists. Refusing to overwrite.");
    }

    let password = prompt_password("Password: ")?;
    let confirm = prompt_password("Confirm password: ")?;

    if password != confirm {
        bail!("Passwords do not match.");
    }
    if password.is_empty() {
        bail!("Password cannot be empty.");
    }

    // === High-quality Argon2id parameters ===
    // Since speed is not a priority, we use stronger parameters for better key quality.
    let params = Params::new(
        256 * 1024, // 256 MiB memory (increased for higher quality)
        6,          // 6 iterations (increased)
        4,          // 4 lanes of parallelism
        Some(32),   // 256-bit output
    )
    .map_err(|e| anyhow::anyhow!("Invalid Argon2 parameters: {}", e))?;

    // Use context as associated data for Argon2id (safe domain separation)
    let argon2 = Argon2::new_with_secret(
        KEY_CONTEXT,
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create Argon2 instance: {}", e))?;

    let mut key_material = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), b"keygen1-salt-v1", &mut key_material)
        .map_err(|e| anyhow::anyhow!("Argon2 hashing failed: {}", e))?;

    // === BLAKE3 XOF with rich domain separation ===
    // We include context, version, and size for strong separation.
    let blake3_context = format!(
        "keygen1-v3:context={}:size={}",
        String::from_utf8_lossy(KEY_CONTEXT),
        args.size
    );

    let mut hasher = Hasher::new_derive_key(&blake3_context);
    hasher.update(&key_material);
    let mut xof = hasher.finalize_xof();

    // Create output file
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("Failed to create key.key")?;

    let mut writer = BufWriter::new(file);

    // Progress bar for large files
    let pb = if args.size > 100 * 1024 * 1024 {
        let bar = ProgressBar::new(args.size);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(bar)
    } else {
        None
    };

    let mut remaining = args.size;
    let mut buffer = [0u8; CHUNK_SIZE];

    while remaining > 0 {
        let chunk = remaining.min(CHUNK_SIZE as u64) as usize;
        xof.fill(&mut buffer[..chunk]);
        writer.write_all(&buffer[..chunk])?;
        remaining -= chunk as u64;

        if let Some(ref bar) = pb {
            bar.inc(chunk as u64);
        }
    }

    writer.flush()?;
    if let Some(bar) = pb {
        bar.finish_with_message("Key generation complete");
    }

    println!("Successfully created key.key ({} bytes)", args.size);
    println!("Using context: {}", String::from_utf8_lossy(KEY_CONTEXT));
    Ok(())
}
