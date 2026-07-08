# keygen1

A modern CLI tool to generate **deterministic, high-quality cryptographic key files** from a password.

## Features

- **Strong security**: Uses **Argon2id** (memory-hard password hashing) followed by **BLAKE3 XOF** expansion.
- **Resistant to brute-force**: Argon2id with 64 MiB memory usage makes offline attacks significantly harder compared to fast hashes.
- **Deterministic**: Same password + size = identical `key.key` every time.
- **Arbitrary length**: Supports any size from 1 byte up to 20 GiB.
- **No repetition**: Output is generated via BLAKE3's extendable-output function — never repeats short patterns.
- **Clean UX**: Proper hidden password input + progress bar for large files.
- **Safe by default**: Refuses to overwrite an existing `key.key` file.
- **Modern Rust**: Built for Rust 1.96+ with edition 2024.

## Why This Design?

Most simple tools just hash the password with BLAKE3/SHA-256 and expand the output. This is fast but weak against password brute-forcing.

`keygen1` does it properly:

1. **Argon2id** first — memory-hard KDF (recommended by OWASP).
2. **BLAKE3 XOF** second — for efficient, cryptographically strong expansion to any length.

This combination gives you both **password brute-force resistance** and **high-quality long output**.

## Requirements

- Rust 1.96 or newer
- A reasonably modern CPU (Argon2id is CPU + memory intensive)

## Installation

```bash
git clone <repo-url>
cd keygen1
cargo build --release
```

The binary will be at `target/release/keygen1`.

## Usage

```bash
keygen1 <size_in_bytes>
```

### Examples

```bash
# 1 MiB key
keygen1 1048576

# 100 MiB key
keygen1 104857600

# 1 GiB key
keygen1 1073741824

# Maximum size (20 GiB)
keygen1 21474836480
```

The tool will:
1. Prompt for a password (input is hidden)
2. Ask for confirmation
3. Generate `key.key` in the current directory (or exit if the file already exists)

## How It Works

1. Your password is processed with **Argon2id** (64 MiB memory, 3 iterations) to produce a strong 256-bit seed.
2. This seed is fed into **BLAKE3** using its `derive_key` mode with domain separation.
3. BLAKE3's XOF mode then generates exactly the amount of key material you requested.
4. The output is streamed to disk in 1 MiB chunks (low memory usage even at 20 GiB).

## Comparison

| Feature                    | Simple BLAKE3 only | keygen1 (Argon2id + BLAKE3) |
|---------------------------|--------------------|-----------------------------|
| Brute-force resistance    | Weak               | Strong                      |
| Memory-hard KDF           | No                 | Yes (Argon2id)              |
| Domain separation         | Basic              | Strong                      |
| Suitable for real keys    | Okay               | Recommended                 |

## License

This project is released into the public domain. Use it however you like.

---

Made with Rust. Feedback and improvements welcome!
