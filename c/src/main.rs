//! Linux-only OTP-style XOR file encryptor/decryptor using a key.key file
//! placed next to the executable.
//!
//! This program is intentionally written for Linux only.
//! It relies on POSIX rename() semantics (atomic replace of existing files)
//! and makes no attempt to be portable to Windows or macOS.
//! This keeps the code simpler and more reliable.

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, metadata};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::process::exit;

const MAGIC: &[u8] = b"OTPX01";
const CHUNK_SIZE: usize = 8192;

fn print_usage() {
    eprintln!("Usage: otp E|D [--wrap] <file>");
    eprintln!("  otp E file.txt           Encrypts file.txt → file.enc");
    eprintln!("  otp E --wrap file.txt    Encrypts with key wrapping (key can be smaller)");
    eprintln!("  otp D file.enc           Decrypts and restores original filename");
}

fn get_key_path() -> io::Result<std::path::PathBuf> {
    let exe = env::current_exe()?;
    let dir = exe
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "executable has no parent dir"))?;
    Ok(dir.join("key.key"))
}

fn load_key() -> io::Result<Vec<u8>> {
    let key_path = get_key_path()?;
    let k = fs::read(&key_path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("key.key not found at {}", key_path.display()),
            )
        } else {
            e
        }
    })?;

    if k.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "key.key is empty (key must have at least 1 byte)",
        ));
    }
    Ok(k)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        exit(1);
    }
}

fn run() -> io::Result<()> {
    let args: Vec<OsString> = env::args_os().collect();
    if args.len() < 2 {
        print_usage();
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing command",
        ));
    }

    let cmd = args[1].to_string_lossy();
    match cmd.as_ref() {
        "E" | "encrypt" => {
            let (wrap, file) = parse_encrypt_args(&args);
            if file.as_os_str().is_empty() {
                print_usage();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no input file specified for encrypt",
                ));
            }
            do_encrypt(&file, wrap)
        }
        "D" | "decrypt" => {
            let file = parse_file_for_decrypt(&args);
            if file.as_os_str().is_empty() {
                print_usage();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no .enc file specified for decrypt",
                ));
            }
            do_decrypt(&file)
        }
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(()) // success, just showing help
        }
        _ => {
            eprintln!("Unknown command: {}", cmd);
            print_usage();
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown command",
            ))
        }
    }
}

fn parse_encrypt_args(args: &[OsString]) -> (bool, std::path::PathBuf) {
    let mut wrap = false;
    let mut file = std::path::PathBuf::new();
    for arg in args.iter().skip(2) {
        if arg == "--wrap" {
            wrap = true;
        } else if file.as_os_str().is_empty() {
            file = arg.into();
        }
    }
    (wrap, file)
}

fn parse_file_for_decrypt(args: &[OsString]) -> std::path::PathBuf {
    let mut file = std::path::PathBuf::new();
    for arg in args.iter().skip(2) {
        if let Some(s) = arg.to_str() {
            if s.starts_with('-') {
                if s == "--wrap" {
                    eprintln!("Warning: --wrap is ignored for decrypt (mode is stored in the file)");
                }
                continue;
            }
        }
        if file.as_os_str().is_empty() {
            file = arg.into();
        }
    }
    file
}

/// Single reusable streaming XOR helper (Linux-only build).
/// Allocates only one buffer and XORs in place.
fn xor_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    key: &[u8],
    mode: u8,
) -> io::Result<()> {
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut key_pos: usize = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }

        for i in 0..n {
            let k_byte = if mode == 1 {
                key[key_pos % key.len()]
            } else {
                if key_pos >= key.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "key file too small",
                    ));
                }
                key[key_pos]
            };
            buf[i] ^= k_byte;
            key_pos += 1;
        }

        writer.write_all(&buf[..n])?;
    }
    Ok(())
}

fn do_encrypt(file: &Path, wrap: bool) -> io::Result<()> {
    if !file.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("input file not found: {}", file.display()),
        ));
    }
    if !file.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", file.display()),
        ));
    }

    let key = load_key()?;
    let mode: u8 = if wrap { 1 } else { 0 };

    let data_len = metadata(file)?.len() as usize;
    if mode == 0 && key.len() < data_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "key file too small",
        ));
    }

    // Store original filename bytes (supports non-UTF-8 filenames on Linux)
    let file_name = file.file_name().unwrap_or_else(|| std::ffi::OsStr::new("recovered_file"));
    let name_bytes = file_name.as_encoded_bytes();

    if name_bytes.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "filename too long to store (> 65535 bytes)",
        ));
    }
    let name_len = name_bytes.len() as u16;

    let mut header = Vec::with_capacity(MAGIC.len() + 1 + 2 + name_bytes.len());
    header.extend_from_slice(MAGIC);
    header.push(mode);
    header.extend_from_slice(&name_len.to_le_bytes());
    header.extend_from_slice(name_bytes);

    let enc_path = file.with_extension("enc");
    let tmp_path = enc_path.with_extension("enc.tmp");

    let mut tmp_file = File::create(&tmp_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Failed to create temporary file {}: {}", tmp_path.display(), e),
        )
    })?;

    tmp_file.write_all(&header)?;

    let mut input_file = File::open(file)?;

    xor_stream(&mut input_file, &mut tmp_file, &key, mode)?;

    if let Err(e) = tmp_file.sync_all() {
        eprintln!("Warning: failed to sync temp file (continuing): {}", e);
    }
    drop(tmp_file);

    // On Linux, rename() atomically replaces an existing destination file.
    fs::rename(&tmp_path, &enc_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        io::Error::new(
            e.kind(),
            format!("Failed to rename temp to {}: {}", enc_path.display(), e),
        )
    })?;

    println!("Encrypted successfully: {} → {}", file.display(), enc_path.display());
    Ok(())
}

fn do_decrypt(file: &Path) -> io::Result<()> {
    if !file.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("encrypted file not found: {}", file.display()),
        ));
    }

    let key = load_key()?;

    let mut enc_file = File::open(file)?;

    let mut header_buf = vec![0u8; MAGIC.len() + 1 + 2];
    enc_file.read_exact(&mut header_buf)?;

    if &header_buf[0..MAGIC.len()] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a valid OTPX encrypted file (bad magic)",
        ));
    }

    let mode = header_buf[MAGIC.len()];
    if mode > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid mode byte in header",
        ));
    }

    let name_len = u16::from_le_bytes([
        header_buf[MAGIC.len() + 1],
        header_buf[MAGIC.len() + 2],
    ]) as usize;

    let mut name_buf = vec![0u8; name_len];
    if name_len > 0 {
        enc_file.read_exact(&mut name_buf)?;
    }

    // Reconstruct original filename from raw bytes stored in the header.
    // This supports non-UTF-8 filenames on Linux.
    let orig_name = std::ffi::OsString::from_vec(name_buf);
    if orig_name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "corrupt encrypted file (empty original filename)",
        ));
    }

    let header_end = MAGIC.len() + 1 + 2 + name_len;

    let file_len = metadata(file)?.len();
    if file_len < header_end as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "corrupt file (shorter than header)",
        ));
    }
    let ct_len = (file_len - header_end as u64) as usize;

    if mode == 0 && key.len() < ct_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "key file too small",
        ));
    }

    let output_dir = file.parent().unwrap_or_else(|| Path::new("."));
    let output_path = output_dir.join(&orig_name);
    let tmp_name = format!("{}.tmp", orig_name.to_string_lossy());
    let tmp_path = output_dir.join(tmp_name);

    let mut tmp_file = File::create(&tmp_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Failed to create temp output {}: {}", tmp_path.display(), e),
        )
    })?;

    xor_stream(&mut enc_file, &mut tmp_file, &key, mode)?;

    if let Err(e) = tmp_file.sync_all() {
        eprintln!("Warning: fsync failed on temp plaintext (continuing): {}", e);
    }
    drop(tmp_file);

    // On Linux this rename() is atomic and will replace any existing file.
    if let Err(e) = fs::rename(&tmp_path, &output_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(io::Error::new(
            e.kind(),
            format!(
                "Failed to finalize decrypted file {}: {}",
                output_path.display(),
                e
            ),
        ));
    }

    println!(
        "Decrypted successfully: {} -> {}",
        file.display(),
        output_path.display()
    );
    Ok(())
}