# crypt

A production-grade command-line tool for encrypting and decrypting single files using modern, audited cryptography.

**Features**
- Streaming encryption/decryption (constant memory usage — works with 10 TiB+ files)
- Argon2id password-based key derivation (64 MiB memory, 3 iterations)
- XChaCha20Poly1305 authenticated encryption
- Per-chunk independent authentication (tamper detection, truncation protection, reordering protection)
- Atomic writes (never leaves partial files)
- Password confirmation on encryption
- Zeroization of sensitive data (passwords and keys)
- Strict format validation and clear error messages
- Cross-platform (Linux, macOS, Windows)

## Cryptography

- **Key Derivation**: Argon2id (memory-hard, side-channel resistant)
  - Memory: 64 MiB
  - Iterations: 3
  - Parallelism: 1
- **Encryption**: XChaCha20Poly1305 (192-bit nonce, fast constant-time implementation)
- **Chunk Size**: 1 MiB (streaming with independent authentication per chunk)
- **File Format**: Custom binary format with magic bytes, version, salt, Argon2 parameters, nonce prefix, original size, and encrypted chunks.

The design ensures that tampering with any part of the file (header, any chunk, reordering, truncation, or appended data) will cause decryption to fail.

## Installation

### From Source (Recommended)

```bash
git clone https://github.com/yourusername/crypt.git
cd crypt
cargo build --release
```

The binary will be at `target/release/crypt`.

### Requirements
- Rust 1.85+ (edition 2024)
- A modern C compiler (for building dependencies)

## Usage

```bash
# Encrypt a file
crypt document.pdf

# Decrypt a file (auto-detected by .enc extension)
crypt document.pdf.enc
```

### What happens

| Input File          | Action     | Output File          |
|---------------------|------------|----------------------|
| `report.pdf`        | Encrypt    | `report.pdf.enc`     |
| `report.pdf.enc`    | Decrypt    | `report.pdf`         |
| `archive.tar.gz`    | Encrypt    | `archive.tar.gz.enc` |
| `archive.tar.gz.enc`| Decrypt    | `archive.tar.gz`     |

### Behavior
- Prompts for password (and confirmation when encrypting)
- Never overwrites existing files
- Uses atomic temp file + rename for safety
- Fails safely on any corruption or wrong password

## File Format (v1)

```
Offset  Size   Description
0       8      Magic: "CRYPTENC"
8       1      Version (1)
9       1      Flags (0)
10      16     Salt (Argon2id)
26      4      Argon2 memory cost (KiB)
30      4      Argon2 time cost
34      1      Argon2 parallelism
35      3      Reserved
38      24     Nonce prefix
62      8      Original plaintext size (u64)
70      ...    Encrypted chunks (XChaCha20Poly1305)
```

Each chunk is independently authenticated using a unique nonce derived from the prefix + chunk number + AAD containing the chunk number.

## Security Properties

- Wrong password → authentication failure
- Any bit flip in header or ciphertext → authentication failure
- Truncated file → clear error
- Reordered chunks → authentication failure
- Appended garbage → rejected
- No partial plaintext is ever written on failure

## Limitations (by design)

- Single file only (no directories or archives)
- No compression
- No multiple recipients
- Header metadata (salt, size, nonce prefix) is not encrypted

## License

MIT OR Apache-2.0

## Acknowledgments

Built with:
- `argon2`
- `chacha20poly1305`
- `clap`
- `anyhow`
- `zeroize`
- `rpassword`

---

**crypt** — Simple. Secure. Production-grade.