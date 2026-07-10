# keygen1

**A high-quality CLI tool for generating deterministic cryptographic key files from a password.**

`keygen1` produces long, deterministic, high-entropy-looking keys using modern cryptographic primitives. It is designed for situations where you need **reproducible yet strong keys** derived from a memorable password.

---

## Features

- **Strong password protection**: Uses **Argon2id** (memory-hard KDF) with high parameters (256 MiB memory, 6 iterations).
- **High-quality output**: Expands the derived material using **BLAKE3 XOF** (extendable-output function).
- **Fully deterministic**: The same password + size + context always produces the exact same `key.key`.
- **No short repetition**: Output has excellent statistical properties with an extremely large period.
- **Compile-time context**: Safely customize keys for different projects/purposes without weakening security.
- **Large file support**: Efficiently generates keys up to 20 GiB with low memory usage and progress reporting.
- **Safe by default**: Refuses to overwrite existing `key.key` files.
- **Clean UX**: Hidden password input with confirmation and progress bar for large files.
- **Modern Rust**: Built for Rust 1.96+ with edition 2024.

---

## Why This Design?

Many simple tools directly hash the password with BLAKE3 or SHA-256. While fast, this offers little protection against password brute-forcing.

`keygen1` uses a two-stage approach that is significantly stronger:

1. **Argon2id** (first stage)
   - Memory-hard key derivation function
   - Winner of the Password Hashing Competition
   - Recommended by OWASP
   - Provides strong resistance to GPU/ASIC brute-force attacks

2. **BLAKE3 XOF** (second stage)
   - Modern, high-speed cryptographic hash with extendable output
   - Excellent statistical randomness properties
   - Strong domain separation support via `derive_key`

This combination gives you both **strong password security** and **high-quality long output**.

---

## Security Considerations

**Important**: `keygen1` generates a **deterministic pseudorandom keystream** from a password. It is **not** a true One-Time Pad.

### Key Points

- **Password reuse is dangerous**: Using the same password to generate keys for multiple files is equivalent to keystream reuse. Avoid this for sensitive applications.
- **Security depends on your password**: Argon2id helps a lot, but a weak or commonly used password can still be attacked.
- **Best suited for**:
  - Reproducible builds and testing
  - Internal tools and infrastructure
  - Situations where you need deterministic keys from a strong password
- **Not recommended for**:
  - High-security encryption requiring forward secrecy
  - Scenarios where true randomness is preferred
  - Production systems where keys might be reused across different data

Treat any generated key with the same care as any other cryptographic key material.

---

## Compile-Time Context (Advanced Feature)

`keygen1` includes a safe, compile-time tweakable value called `KEY_CONTEXT`.

### Location

Defined near the top of `src/main.rs`:

```rust
const KEY_CONTEXT: &[u8] = b"default-keygen1-context";
```

### How to Customize

1. Edit `src/main.rs`
2. Change the `KEY_CONTEXT` constant
3. Rebuild:
   ```bash
   cargo build --release
   ```

### Recommended Length

- **Maximum recommended**: 256 bytes
- **Typical good length**: 15–80 bytes
- Short, meaningful contexts are preferred for readability.

### Safety Guarantee

Changing `KEY_CONTEXT` **cannot weaken** the cryptographic strength of the output. It only provides additional domain separation. Different contexts produce completely independent keys.

### Example

```rust
const KEY_CONTEXT: &[u8] = b"company-project-alpha-backups-2026";
```

This allows you to create different "key universes" for different projects while maintaining full determinism and high quality.

---

## Requirements

- Rust 1.96 or newer
- A reasonably modern CPU (Argon2id is memory and CPU intensive)

---

## Installation

```bash
git clone <your-repo-url>
cd keygen1
cargo build --release
```

The binary will be available at:

```
target/release/keygen1
```

---

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

The program will:
1. Prompt for a password (input is hidden)
2. Ask for password confirmation
3. Generate `key.key` in the current directory (fails if the file already exists)

---

## How It Works

1. The password is processed using **Argon2id** (256 MiB memory, 6 iterations) along with the compile-time context. This produces a strong 256-bit seed.
2. The seed is fed into **BLAKE3** using `new_derive_key()` with a rich context string that includes the user context and requested size.
3. BLAKE3's extendable-output function (XOF) generates exactly the amount of key material requested.
4. The output is streamed to disk in 1 MiB chunks for efficiency.

---

## Comparison

| Feature                        | Plain BLAKE3 / SHA-256 | keygen1 (Argon2id + BLAKE3)      |
|--------------------------------|------------------------|----------------------------------|
| Brute-force resistance         | Weak                   | Good                             |
| Memory-hard KDF                | No                     | Yes (Argon2id)                   |
| Domain separation              | Basic                  | Strong                           |
| Compile-time customization     | No                     | Yes (safe context)               |
| Suitable for reproducible keys | Okay                   | Good                             |
| Statistical output quality     | Very Good              | Excellent                        |

---

## License

This project is released into the public domain. You may use, modify, and distribute it however you like.

---

*Made with Rust. Honest feedback welcome.*
