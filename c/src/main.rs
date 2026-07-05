use std::env;
use std::fs::{self, File, metadata};
use std::io::{self, Read, Write};
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

fn load_key() -> Vec<u8> {
    let key_path = match get_key_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to determine key.key location next to executable: {}", e);
            exit(1);
        }
    };
    match fs::read(&key_path) {
        Ok(k) => {
            if k.is_empty() {
                eprintln!("key.key is empty (key must have at least 1 byte)");
                exit(1);
            }
            k
        }
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                eprintln!("key.key not found at {}", key_path.display());
            } else {
                eprintln!("Failed to read key.key: {}", e);
            }
            exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        exit(1);
    }

    let cmd = args[1].as_str();
    match cmd {
        "E" | "encrypt" => {
            let (wrap, file) = parse_encrypt_args(&args);
            if file.is_empty() {
                eprintln!("Error: no input file specified for encrypt");
                print_usage();
                exit(1);
            }
            do_encrypt(&file, wrap);
        }
        "D" | "decrypt" => {
            let file = parse_file_for_decrypt(&args);
            if file.is_empty() {
                eprintln!("Error: no .enc file specified for decrypt");
                print_usage();
                exit(1);
            }
            do_decrypt(&file);
        }
        "-h" | "--help" | "help" => {
            print_usage();
            exit(0);
        }
        _ => {
            eprintln!("Unknown command: {}", cmd);
            print_usage();
            exit(1);
        }
    }
}

fn parse_encrypt_args(args: &[String]) -> (bool, String) {
    let mut wrap = false;
    let mut file = String::new();
    for arg in args.iter().skip(2) {
        match arg.as_str() {
            "--wrap" => wrap = true,
            _ => {
                if file.is_empty() {
                    file = arg.clone();
                }
            }
        }
    }
    (wrap, file)
}

fn parse_file_for_decrypt(args: &[String]) -> String {
    let mut file = String::new();
    for arg in args.iter().skip(2) {
        if arg.starts_with('-') {
            if arg == "--wrap" {
                eprintln!("Warning: --wrap is ignored for decrypt (mode is stored in the file)");
            }
            continue;
        }
        if file.is_empty() {
            file = arg.clone();
        }
    }
    file
}

fn do_encrypt(file: &str, wrap: bool) {
    let input_path = Path::new(file);
    if !input_path.exists() {
        eprintln!("Error: input file not found: {}", file);
        exit(1);
    }
    if !input_path.is_file() {
        eprintln!("Error: {} is not a regular file", file);
        exit(1);
    }

    let key = load_key();
    let mode: u8 = if wrap { 1 } else { 0 };

    // Get size for early check (fail fast)
    let data_len = match metadata(input_path) {
        Ok(m) => m.len() as usize,
        Err(e) => {
            eprintln!("Failed to read metadata for {}: {}", file, e);
            exit(1);
        }
    };

    if mode == 0 && key.len() < data_len {
        eprintln!("key file too small");
        exit(1);
    }

    // Original filename (basename only, no directory)
    let orig_name = input_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "recovered_file".to_string());

    let name_bytes = orig_name.as_bytes();
    if name_bytes.len() > u16::MAX as usize {
        eprintln!("Error: filename too long to store (> 65535 bytes)");
        exit(1);
    }
    let name_len = name_bytes.len() as u16;

    // Build header
    let mut header = Vec::with_capacity(MAGIC.len() + 1 + 2 + name_bytes.len());
    header.extend_from_slice(MAGIC);
    header.push(mode);
    header.extend_from_slice(&name_len.to_le_bytes());
    header.extend_from_slice(name_bytes);

    // Output path: always create .enc file (safer)
    let enc_path = input_path.with_extension("enc");
    let tmp_path = enc_path.with_extension("enc.tmp");

    // Create temp file for atomic write
    let mut tmp_file = match File::create(&tmp_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to create temporary file {}: {}", tmp_path.display(), e);
            exit(1);
        }
    };

    // Write header
    if let Err(e) = tmp_file.write_all(&header) {
        eprintln!("Failed to write header to temp file: {}", e);
        let _ = fs::remove_file(&tmp_path);
        exit(1);
    }

    // Open input for streaming
    let mut input_file = match File::open(input_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open input file {}: {}", file, e);
            let _ = fs::remove_file(&tmp_path);
            exit(1);
        }
    };

    // Stream XOR and write ciphertext
    let mut chunk = vec![0u8; CHUNK_SIZE];
    let mut key_pos: usize = 0;

    loop {
        let n = match input_file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                eprintln!("Read error from input: {}", e);
                let _ = fs::remove_file(&tmp_path);
                exit(1);
            }
        };

        let mut ct_chunk = vec![0u8; n];
        for i in 0..n {
            let k_byte = if mode == 1 {
                key[key_pos % key.len()]
            } else {
                if key_pos >= key.len() {
                    eprintln!("key file too small");
                    let _ = fs::remove_file(&tmp_path);
                    exit(1);
                }
                key[key_pos]
            };
            ct_chunk[i] = chunk[i] ^ k_byte;
            key_pos += 1;
        }

        if let Err(e) = tmp_file.write_all(&ct_chunk) {
            eprintln!("Write error to temp file: {}", e);
            let _ = fs::remove_file(&tmp_path);
            exit(1);
        }
    }

    // Ensure data is on disk before renaming
    if let Err(e) = tmp_file.sync_all() {
        eprintln!("Warning: failed to sync temp file (continuing): {}", e);
    }

    drop(tmp_file);

    // Atomic rename (safe on Linux when on same filesystem)
    if let Err(e) = fs::rename(&tmp_path, &enc_path) {
        eprintln!("Failed to rename temp to {}: {}", enc_path.display(), e);
        let _ = fs::remove_file(&tmp_path);
        exit(1);
    }

    println!("Encrypted successfully: {} → {}", file, enc_path.display());
}

fn do_decrypt(file: &str) {
    let enc_path = Path::new(file);
    if !enc_path.exists() {
        eprintln!("Error: encrypted file not found: {}", file);
        exit(1);
    }

    let key = load_key();

    // Open and read header (small, even if name is max 65k)
    let mut enc_file = match File::open(enc_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open {}: {}", file, e);
            exit(1);
        }
    };

    let mut header_buf = vec![0u8; MAGIC.len() + 1 + 2]; // 9 bytes
    if let Err(e) = enc_file.read_exact(&mut header_buf) {
        eprintln!("Failed to read header (file too small or corrupt): {}", e);
        exit(1);
    }

    if &header_buf[0..MAGIC.len()] != MAGIC {
        eprintln!("Error: not a valid OTPX encrypted file (bad magic)");
        exit(1);
    }

    let mode = header_buf[MAGIC.len()];
    if mode > 1 {
        eprintln!("Error: invalid mode byte in header");
        exit(1);
    }

    let name_len = u16::from_le_bytes([
        header_buf[MAGIC.len() + 1],
        header_buf[MAGIC.len() + 2],
    ]) as usize;

    let mut name_buf = vec![0u8; name_len];
    if name_len > 0 {
        if let Err(e) = enc_file.read_exact(&mut name_buf) {
            eprintln!("Corrupt header: filename truncated ({})", e);
            exit(1);
        }
    }

    let orig_name = String::from_utf8_lossy(&name_buf).into_owned();
    if orig_name.is_empty() {
        eprintln!("Error: corrupt encrypted file (empty original filename)");
        exit(1);
    }

    let header_end = MAGIC.len() + 1 + 2 + name_len;

    // Get ct length from metadata for early size check (fail fast, no partial output)
    let enc_meta = match metadata(enc_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to get metadata for {}: {}", file, e);
            exit(1);
        }
    };
    let file_len = enc_meta.len();
    if file_len < header_end as u64 {
        eprintln!("Error: corrupt file (shorter than header)");
        exit(1);
    }
    let ct_len = (file_len - header_end as u64) as usize;

    if mode == 0 && key.len() < ct_len {
        eprintln!("key file too small");
        exit(1);
    }

    // Current file pos is already after header (we read_exact it)
    // Prepare output next to .enc file
    let output_dir = enc_path.parent().unwrap_or_else(|| Path::new("."));
    let output_path = output_dir.join(&orig_name);
    let tmp_name = format!("{}.tmp", orig_name);
    let tmp_path = output_dir.join(&tmp_name);

    let mut tmp_file = match File::create(&tmp_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to create temp output {}: {}", tmp_path.display(), e);
            exit(1);
        }
    };

    // Stream decrypt
    let mut chunk = vec![0u8; CHUNK_SIZE];
    let mut key_pos: usize = 0;

    loop {
        let n = match enc_file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                eprintln!("Read error during decryption: {}", e);
                let _ = fs::remove_file(&tmp_path);
                exit(1);
            }
        };

        let mut pt_chunk = vec![0u8; n];
        for i in 0..n {
            let k_byte = if mode == 1 {
                key[key_pos % key.len()]
            } else {
                if key_pos >= key.len() {
                    eprintln!("key file too small");
                    let _ = fs::remove_file(&tmp_path);
                    exit(1);
                }
                key[key_pos]
            };
            pt_chunk[i] = chunk[i] ^ k_byte;
            key_pos += 1;
        }

        if let Err(e) = tmp_file.write_all(&pt_chunk) {
            eprintln!("Write error during decryption: {}", e);
            let _ = fs::remove_file(&tmp_path);
            exit(1);
        }
    }

    if let Err(e) = tmp_file.sync_all() {
        eprintln!("Warning: fsync failed on temp plaintext (continuing): {}", e);
    }

    drop(tmp_file);

    // Remove existing output if present (for cross-platform overwrite via rename)
    if output_path.exists() {
        if let Err(e) = fs::remove_file(&output_path) {
            eprintln!("Cannot remove existing file {}: {}", output_path.display(), e);
            let _ = fs::remove_file(&tmp_path);
            exit(1);
        }
    }

    // Atomic finalize
    if let Err(e) = fs::rename(&tmp_path, &output_path) {
        eprintln!("Failed to finalize decrypted file {}: {}", output_path.display(), e);
        let _ = fs::remove_file(&tmp_path);
        exit(1);
    }

    println!("Decrypted successfully: {} -> {}", file, output_path.display());
}