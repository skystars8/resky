use std::env;
use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::path::Path;
use std::process::{Command, Stdio};

const MAX_SIZE: u64 = 20 * 1024 * 1024 * 1024; // 20 GiB
const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB chunks for efficiency

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <size_in_bytes>", args[0]);
        eprintln!("  Creates a deterministic key.key file of the given size (1 byte to 20 GiB).");
        eprintln!("  Prompts for password twice (must match). Refuses to overwrite existing key.key.");
        eprintln!("  The key is derived deterministically from the password and size; no simple repetition.");
        std::process::exit(1);
    }

    let size_str = &args[1];
    let size: u64 = match size_str.parse() {
        Ok(n) if n >= 1 && n <= MAX_SIZE => n,
        Ok(n) if n == 0 => {
            eprintln!("Error: size must be at least 1 byte.");
            std::process::exit(1);
        }
        Ok(_) => {
            eprintln!("Error: size must be between 1 and {} bytes (20 GiB).", MAX_SIZE);
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("Error: '{}' is not a valid number of bytes.", size_str);
            eprintln!("Example: {} 1048576   # for 1 MiB", args[0]);
            std::process::exit(1);
        }
    };

    // Check for existing key.key BEFORE prompting for password
    if Path::new("key.key").exists() {
        eprintln!("Error: key.key already exists in this directory. Refusing to overwrite.");
        std::process::exit(1);
    }

    // Prompt for password twice
    let password = match read_password("Enter password: ") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error reading password: {}", e);
            std::process::exit(1);
        }
    };

    let confirm = match read_password("Confirm password: ") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error reading password: {}", e);
            std::process::exit(1);
        }
    };

    if password != confirm {
        eprintln!("Error: Passwords do not match.");
        std::process::exit(1);
    }

    if password.is_empty() {
        eprintln!("Warning: Empty password used. This is insecure but allowed.");
    }

    // Derive deterministic 256-bit seed using OpenSSL SHA-512 (one call)
    let seed = derive_seed(&password, size);

    // Initialize fast PRNG from seed (Xoshiro256**)
    let mut rng = Xoshiro256StarStar::new(seed);

    // Create the file
    let file = match File::create("key.key") {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error creating key.key: {}", e);
            std::process::exit(1);
        }
    };
    let mut writer = BufWriter::new(file);

    // Generate and write the key in chunks (streaming, low memory)
    let mut remaining = size;
    let mut written: u64 = 0;
    let show_progress = size > 10 * 1024 * 1024; // progress for >10 MiB

    if show_progress {
        eprint!("Generating key.key ({} bytes)...\r", size);
    }

    let mut chunk_buf = vec![0u8; CHUNK_SIZE];

    while remaining > 0 {
        let to_gen = std::cmp::min(remaining as usize, CHUNK_SIZE);
        rng.fill_bytes(&mut chunk_buf[..to_gen]);
        if let Err(e) = writer.write_all(&chunk_buf[..to_gen]) {
            eprintln!("\nError writing to key.key: {}", e);
            std::process::exit(1);
        }
        remaining -= to_gen as u64;
        written += to_gen as u64;

        if show_progress {
            let pct = (written * 100 / size) as u32;
            eprint!("\rGenerating key.key: {}% ({}/{} bytes)", pct, written, size);
        }
    }

    if let Err(e) = writer.flush() {
        eprintln!("\nError flushing key.key: {}", e);
        std::process::exit(1);
    }

    if show_progress {
        eprintln!("\rGenerating key.key: 100% ({}/{} bytes) - Done!                    ", size, size);
    } else {
        eprintln!("Successfully created key.key ({} bytes).", size);
    }
}

/// Read password from terminal with echo disabled.
/// Uses `std::io::IsTerminal` (stable since Rust 1.70) + stty for maximum compatibility.
/// Suppresses stty error messages and has safe restore logic.
fn read_password(prompt: &str) -> io::Result<String> {
    eprint!("{}", prompt);
    io::stdout().flush()?;

    let stdin = std::io::stdin();
    let is_tty = stdin.is_terminal();

    let saved_state: Option<String> = if is_tty {
        // Try to get current terminal state
        match Command::new("stty")
            .arg("-g")
            .stderr(std::process::Stdio::null())
            .output()
        {
            Ok(output) if output.status.success() => {
                let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if s.is_empty() { None } else { Some(s) }
            }
            _ => None,
        }
    } else {
        None
    };

    if is_tty {
        // Disable echo (ignore errors, we have fallbacks)
        let _ = Command::new("stty")
            .arg("-echo")
            .stderr(std::process::Stdio::null())
            .status();
    }

    let mut line = String::new();
    let read_res = stdin.read_line(&mut line);

    // Restore terminal
    if let Some(ref state) = saved_state {
        let _ = Command::new("stty")
            .arg(state)
            .stderr(std::process::Stdio::null())
            .status();
    } else if is_tty {
        // Safety fallback: force echo back on
        let _ = Command::new("stty")
            .arg("echo")
            .stderr(std::process::Stdio::null())
            .status();
    }

    if is_tty {
        eprintln!(); // newline after hidden input
    }

    read_res?;
    // Remove only the line ending(s), keep internal whitespace/spaces in password
    Ok(line.trim_end_matches(&['\r', '\n'][..]).to_string())
}

/// Derive a deterministic 32-byte seed from password + size using OpenSSL SHA-512.
/// This ensures cryptographic strength mixing for the initial seed.
fn derive_seed(password: &str, size: u64) -> [u8; 32] {
    let context = format!("keygen1-v1:size={}", size);
    // Feed context then password into hash (order doesn't matter much for one-shot)
    let mut cmd = match Command::new("openssl")
        .arg("dgst")
        .arg("-sha512")
        .arg("-binary")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error spawning openssl (is it installed?): {}", e);
            std::process::exit(1);
        }
    };

    {
        let mut stdin = cmd.stdin.take().expect("openssl stdin pipe failed");
        if let Err(e) = stdin.write_all(context.as_bytes()) {
            eprintln!("Error writing to openssl stdin: {}", e);
            std::process::exit(1);
        }
        if let Err(e) = stdin.write_all(password.as_bytes()) {
            eprintln!("Error writing password to openssl stdin: {}", e);
            std::process::exit(1);
        }
        // stdin dropped here -> EOF
    }

    let output = match cmd.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error waiting for openssl: {}", e);
            std::process::exit(1);
        }
    };

    if !output.status.success() {
        eprintln!("openssl dgst failed with status: {:?}", output.status);
        if !output.stderr.is_empty() {
            eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        }
        std::process::exit(1);
    }

    if output.stdout.len() < 64 {
        eprintln!("Unexpected short output from openssl sha512");
        std::process::exit(1);
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&output.stdout[0..32]);
    seed
}

/// Xoshiro256** PRNG - fast, deterministic, huge period (2^256-1), excellent quality.
/// Seeded from the password-derived seed. Output never repeats in practice for our sizes.
struct Xoshiro256StarStar {
    state: [u64; 4],
}

impl Xoshiro256StarStar {
    fn new(seed: [u8; 32]) -> Self {
        let mut state = [0u64; 4];
        for i in 0..4 {
            let start = i * 8;
            let end = start + 8;
            state[i] = u64::from_le_bytes(seed[start..end].try_into().expect("seed slice"));
        }
        // Avoid all-zero state (would produce all zeros)
        if state.iter().all(|&x| x == 0) {
            state[0] = 0x9e3779b97f4a7c15; // golden ratio-ish
            state[1] = 0xf4a7c159e3779b97;
            state[2] = 0x7f4a7c159e3779b9;
            state[3] = 0x4a7c159e3779b97f;
        }
        // Mix a bit
        let mut rng = Self { state };
        for _ in 0..16 {
            rng.next_u64();
        }
        rng
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        let result = starstar(self.state[1]);
        let t = self.state[1] << 17;
        self.state[2] ^= self.state[0];
        self.state[3] ^= self.state[1];
        self.state[1] ^= self.state[2];
        self.state[0] ^= self.state[3];
        self.state[2] ^= t;
        self.state[3] = self.state[3].rotate_left(45);
        result
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        let len = dest.len();
        while i + 8 <= len {
            let val = self.next_u64().to_le_bytes();
            dest[i..i + 8].copy_from_slice(&val);
            i += 8;
        }
        if i < len {
            let val = self.next_u64().to_le_bytes();
            let rem = len - i;
            dest[i..i + rem].copy_from_slice(&val[..rem]);
        }
    }
}

#[inline(always)]
fn starstar(x: u64) -> u64 {
    // Xoshiro256** finalizer
    let x = x.wrapping_mul(5);
    (x.rotate_left(7)).wrapping_mul(9)
}