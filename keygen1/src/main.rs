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

#[derive(Parser, Debug)]
#[command(name = "keygen1", version, about = "Generate deterministic cryptographic key files from a password")]
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

    // === Argon2id parameters ===
    let params = Params::new(64 * 1024, 3, 4, Some(32))
        .map_err(|e| anyhow::anyhow!("Invalid Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    // Derive 256-bit key material using Argon2id
    let mut key_material = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), b"keygen1-salt-v1", &mut key_material)
        .map_err(|e| anyhow::anyhow!("Argon2 hashing failed: {}", e))?;

    // === BLAKE3 XOF expansion ===
    let mut hasher = Hasher::new_derive_key("keygen1-v2:blake3-xof");
    hasher.update(&key_material);
    hasher.update(args.size.to_le_bytes().as_slice());
    let mut xof = hasher.finalize_xof();

    // Create file (fails if already exists)
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("Failed to create key.key")?;

    let mut writer = BufWriter::new(file);

    // Progress bar only for larger files
    let pb = if args.size > 50 * 1024 * 1024 {
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
    Ok(())
}