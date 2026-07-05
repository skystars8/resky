//! Linux-only strict OTP (one-time pad) XOR processor.
//!
//! Minimal explicit design:
//! - User must always specify both input and output files.
//! - Files contain ONLY the XORed data (no header, no magic, no filename stored).
//! - Maximum simplicity and smallest trusted code base.
//!
//! Because XOR is its own inverse, the exact same operation both "encrypts" and "decrypts".
//! There are no separate E/D modes — just run the tool again on the output to reverse it.

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, metadata};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::process::exit;

const CHUNK_SIZE: usize = 8192;

/// RAII guard that deletes the temporary file on drop unless explicitly committed.
struct TempPath {
    path: std::path::PathBuf,
    committed: bool,
}

impl TempPath {
    fn new(path: std::path::PathBuf) -> Self {
        TempPath { path, committed: false }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  otp <input> <output>     XOR <input> with key.key → <output>");
    eprintln!();
    eprintln!("This operation is symmetric:");
    eprintln!("  • Running once on plaintext produces ciphertext.");
    eprintln!("  • Running again on ciphertext with the same key recovers the plaintext.");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  otp document.pdf document.pdf.enc");
    eprintln!("  otp document.pdf.enc document.pdf");
    eprintln!();
    eprintln!("key.key must be at least as large as the file being processed.");
}

fn get_key_path() -> io::Result<std::path::PathBuf> {
    let exe = env::current_exe()?;
    let dir = exe
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "executable has no parent dir"))?;
    Ok(dir.join("key.key"))
}

fn fsync_dir(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dir = File::open(parent)?;
    dir.sync_all()
}

/// Streaming OTP XOR - constant memory usage.
fn xor_stream<R: Read, K: Read, W: Write>(
    mut data_reader: R,
    mut key_reader: K,
    mut writer: W,
) -> io::Result<()> {
    let mut data_buf = vec![0u8; CHUNK_SIZE];
    let mut key_buf = vec![0u8; CHUNK_SIZE];

    loop {
        let n = data_reader.read(&mut data_buf)?;
        if n == 0 {
            break;
        }

        let mut key_read_total: usize = 0;
        while key_read_total < n {
            let k_n = key_reader.read(&mut key_buf[key_read_total..n])?;
            if k_n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "key file too small",
                ));
            }
            key_read_total += k_n;
        }

        for i in 0..n {
            data_buf[i] ^= key_buf[i];
        }

        writer.write_all(&data_buf[..n])?;
    }

    // Zeroize buffers to avoid leaving key material or plaintext in memory.
    data_buf.fill(0);
    key_buf.fill(0);

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        exit(1);
    }
}

fn run() -> io::Result<()> {
    let args: Vec<OsString> = env::args_os().collect();

    if args.len() != 3 {
        print_usage();
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected exactly two file arguments: <input> <output>",
        ));
    }

    let input = Path::new(&args[1]);
    let output = Path::new(&args[2]);

    if input == output {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input and output paths must be different",
        ));
    }
    if !input.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("input not found: {}", input.display()),
        ));
    }
    if !input.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", input.display()),
        ));
    }
    if output.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("output already exists: {}", output.display()),
        ));
    }

    let key_path = get_key_path()?;
    let data_len = metadata(input)?.len() as usize;
    let key_len = metadata(&key_path)?.len() as usize;

    if key_len < data_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "key file too small",
        ));
    }

    let tmp_path = output.with_extension(
        output
            .extension()
            .map(|e| format!("{}.tmp", e.to_string_lossy()))
            .unwrap_or_else(|| "tmp".into()),
    );

    let mut tmp_writer = BufWriter::new(File::create(&tmp_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Failed to create temp file: {}", tmp_path.display()),
        )
    })?);
    let mut tmp_guard = TempPath::new(tmp_path);

    let input_file = File::open(input)?;
    let key_file = File::open(&key_path)?;

    xor_stream(
        BufReader::new(input_file),
        BufReader::new(key_file),
        &mut tmp_writer,
    )?;

    tmp_writer.flush()?;
    let inner = tmp_writer.into_inner().map_err(|e| e.into_error())?;
    if let Err(e) = inner.sync_all() {
        eprintln!("Warning: sync failed on temp (continuing): {}", e);
    }

    fs::rename(tmp_guard.path(), output).map_err(|e| {
        let _ = fs::remove_file(tmp_guard.path());
        io::Error::new(
            e.kind(),
            format!(
                "Failed to rename temporary file to {}: {}",
                output.display(),
                e
            ),
        )
    })?;

    tmp_guard.commit();

    if let Err(e) = fsync_dir(output) {
        eprintln!("Warning: fsync dir failed (continuing): {}", e);
    }

    println!("Processed: {} → {}", input.display(), output.display());
    Ok(())
}