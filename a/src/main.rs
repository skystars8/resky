// minilock - Simplified single-file encryption tool
// Uses XChaCha20-Poly1305 (from chacha20poly1305 crate) with a HARDCODED key
// Preserves original filename inside the .enc file, just like IronLock

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

const MAGIC: &[u8; 8] = b"MINILOCK";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 24; // XChaCha20 uses 24-byte nonces

/// Default hardcoded 32-byte key (for demonstration only).
///
/// SECURITY WARNING:
/// This key is embedded in the binary. Anyone who can read or reverse the
/// binary can extract it. Only use this for personal / low-risk use cases.
///
/// IMPORTANT: Replace this key with your own random 32-byte key before using!
const KEY: [u8; 32] = [
    0x09, 0xc5, 0x19, 0xb0, 0x65, 0x03, 0xed, 0x06,
    0x18, 0xdc, 0x5f, 0xef, 0x1e, 0xe4, 0x5e, 0xe0,
    0x2b, 0x58, 0xff, 0x89, 0x2f, 0xa4, 0x2e, 0x2a,
    0x9a, 0x98, 0x53, 0x8c, 0x1e, 0x23, 0x8b, 0x76,
];

fn encrypt_file(input_path: &Path) -> Result<(), String> {
    let cipher = XChaCha20Poly1305::new(&KEY.into());

    let plaintext = fs::read(input_path)
        .map_err(|e| format!("Failed to read input file: {}", e))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Get original filename (we store the full original name)
    let original_name = input_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid filename")?
        .to_string();

    // Build header: MAGIC + VERSION + filename_len (u16 BE) + filename + nonce
    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    header.push(VERSION);

    let name_bytes = original_name.as_bytes();
    header.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    header.extend_from_slice(name_bytes);
    header.extend_from_slice(&nonce_bytes);

    // Encrypt with header as AAD
    let payload = Payload {
        msg: &plaintext,
        aad: &header,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| "Encryption failed".to_string())?;

    // Output filename: replace extension with .enc (or append if no extension)
    let stem = input_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let output_path = input_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!("{}.enc", stem));

    // Write header + ciphertext
    let mut output_file = fs::File::create(&output_path)
        .map_err(|e| format!("Failed to create output file: {}", e))?;
    output_file
        .write_all(&header)
        .map_err(|e| format!("Failed to write header: {}", e))?;
    output_file
        .write_all(&ciphertext)
        .map_err(|e| format!("Failed to write ciphertext: {}", e))?;

    println!("Encrypted → {}", output_path.display());
    Ok(())
}

fn decrypt_file(input_path: &Path) -> Result<(), String> {
    let cipher = XChaCha20Poly1305::new(&KEY.into());

    let data = fs::read(input_path)
        .map_err(|e| format!("Failed to read input file: {}", e))?;

    if data.len() < 8 + 1 + 2 + NONCE_LEN {
        return Err("File too small or corrupted".to_string());
    }

    // Parse header
    if &data[0..8] != MAGIC {
        return Err("Not a valid minilock file (bad magic)".to_string());
    }
    if data[8] != VERSION {
        return Err(format!("Unsupported version: {}", data[8]));
    }

    let name_len = u16::from_be_bytes([data[9], data[10]]) as usize;
    let header_len = 8 + 1 + 2 + name_len + NONCE_LEN;

    if data.len() < header_len {
        return Err("Truncated file".to_string());
    }

    let original_name = String::from_utf8(data[11..11 + name_len].to_vec())
        .map_err(|_| "Invalid filename in header".to_string())?;

    let nonce = XNonce::from_slice(&data[11 + name_len..header_len]);

    let ciphertext = &data[header_len..];

    // Decrypt with header as AAD
    let payload = Payload {
        msg: ciphertext,
        aad: &data[..header_len],
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| "Decryption failed (wrong key or corrupted file)".to_string())?;

    // Determine output path (same directory as the .enc file)
    let output_dir = input_path.parent().unwrap_or(Path::new("."));
    let output_path = output_dir.join(&original_name);

    // Write decrypted file
    fs::write(&output_path, plaintext)
        .map_err(|e| format!("Failed to write decrypted file: {}", e))?;

    println!("Decrypted → {}", output_path.display());
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage:");
        eprintln!("  minilock E <file>      # Encrypt");
        eprintln!("  minilock D <file.enc>  # Decrypt");
        eprintln!("\nKey is hardcoded inside the binary — change it in src/main.rs before real use!");
        eprintln!("Only accepts uppercase E or D (single letter).");
        std::process::exit(1);
    }

    let command = &args[1];
    let input = Path::new(&args[2]);

    let result = match command.as_str() {
        "E" => encrypt_file(input),
        "D" => decrypt_file(input),
        _ => {
            eprintln!("Unknown command: {}", command);
            eprintln!("Use 'E' to encrypt or 'D' to decrypt");
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}