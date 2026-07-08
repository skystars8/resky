use anyhow::{bail, Context, Result};
use blake3::Hasher;
use rpassword::prompt_password;
use std::{
    env,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
};

const MAX_SIZE: u64 = 20 * 1024 * 1024 * 1024;
const CHUNK_SIZE: usize = 1024 * 1024;

fn parse_size() -> Result<u64> {
    let arg = env::args()
        .nth(1)
        .context("Usage: keygen <size_in_bytes>")?;

    let size: u64 = arg.parse()?;

    if size == 0 {
        bail!("Size must be at least 1 byte.");
    }

    if size > MAX_SIZE {
        bail!("Maximum size is 20 GiB.");
    }

    Ok(size)
}

fn main() -> Result<()> {
    let size = parse_size()?;

    let path = Path::new("key.key");

    if path.exists() {
        bail!("key.key already exists. Refusing to overwrite.");
    }

    let password1 = prompt_password("Password: ")?;
    let password2 = prompt_password("Confirm : ")?;

    if password1 != password2 {
        bail!("Passwords do not match.");
    }

    if password1.is_empty() {
        bail!("Password may not be empty.");
    }

    // Derive a deterministic seed.
    let mut hasher = Hasher::new();
    hasher.update(password1.as_bytes());

    // Domain separation.
    hasher.update(b"KEYGEN-V1");

    let mut output = hasher.finalize_xof();

    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;

    let mut writer = BufWriter::new(file);

    let mut remaining = size;
    let mut buffer = [0u8; CHUNK_SIZE];

    while remaining > 0 {
        let chunk = remaining.min(CHUNK_SIZE as u64) as usize;

        output.fill(&mut buffer[..chunk]);

        writer.write_all(&buffer[..chunk])?;

        remaining -= chunk as u64;
    }

    writer.flush()?;

    println!("Created key.key ({} bytes)", size);

    Ok(())
}