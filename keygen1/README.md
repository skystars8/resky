# keygen1

A simple, secure CLI tool that generates a **deterministic cryptographic key file** (`key.key`) of any size from a password.

## Features

- **Deterministic output**: The same password + desired size always produces the exact same `key.key` file.
- **No repetition**: Uses a high-quality PRNG (Xoshiro256**) seeded from a SHA-512 hash of the password. The output never repeats short patterns.
- **Any size supported**: From 1 byte up to 20 GiB.
- **Password confirmation**: Asks for the password twice to prevent typos.
- **Safe**: Refuses to overwrite an existing `key.key` file.
- **Low memory**: Streams the key in 1 MiB chunks — works even for very large files.
- **Clean terminal experience**: Proper hidden password input with no ugly `stty` error messages.
- **Zero external Rust dependencies**: Uses only the Rust standard library + system `openssl` and `stty`.

## Requirements

- Rust 1.96 or newer (with edition 2024)
- `openssl` command available in your PATH (usually pre-installed on Linux)

On older Rust versions you can change `edition = "2024"` to `edition = "2021"` in `Cargo.toml` — the code is fully compatible.

## Installation / Build

```bash
git clone <your-repo-url>
cd keygen1
cargo build --release
```

The binary will be at `target/release/keygen1`.

## Usage

```bash
./target/release/keygen1 <size_in_bytes>
```

### Examples

```bash
# Create a 1 MiB key
./target/release/keygen1 1048576

# Create a 100 MiB key
./target/release/keygen1 104857600

# Create a 1 GiB key
./target/release/keygen1 1073741824

# Maximum supported size (20 GiB)
./target/release/keygen1 21474836480
```

The tool will:
1. Ask for a password (hidden input)
2. Ask to confirm the password
3. Create `key.key` in the current directory (or refuse if it already exists)

## How the Key is Generated

1. A context string containing the requested size is combined with your password.
2. This is hashed once using `openssl dgst -sha512` to produce a strong 256-bit seed.
3. The seed initializes a Xoshiro256** PRNG (excellent statistical quality, period of 2²⁵⁶−1).
4. The PRNG output is streamed directly to `key.key` in chunks.

This design ensures:
- Strong mixing of the password
- No obvious repetition or patterns
- Reproducibility across runs and machines

## Why This Tool?

Useful when you need a **reproducible, high-entropy-looking key file** derived from a memorable password (e.g., for testing, reproducible builds, or as a master key seed).

**Note**: This is not a replacement for proper password-based key derivation functions like Argon2 when used in production security systems. It is designed for convenience + determinism.

## License

This project is released into the public domain. Feel free to use, modify, and distribute it however you like.

---

Made with ❤️ in Rust. Contributions and feedback welcome!
