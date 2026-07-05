# otp

**Strict, minimal one-time pad (OTP) encryptor/decryptor** written in Rust.

Designed for explicitness, safety, and a tiny trusted codebase. No magic bytes, no metadata, no surprises.

## Features

- **Pure streaming XOR** — constant memory usage regardless of file size
- **No headers or magic** — the encrypted file contains *only* the ciphertext
- **Atomic & durable writes** — uses a temporary file + `rename` + `fsync`
- **Explicit by design** — you must always specify both input and output files
- **Safety checks**:
  - Rejects identical input and output paths
  - Verifies the key is large enough before starting
  - Prevents overwriting existing output files
- **Security hygiene** — internal buffers are zeroized after use
- **Zero dependencies** — pure `std`, compiles with just `rustc`

## Requirements

- Linux (as designed)
- A `key.key` file placed **next to the `otp` binary**
- The key must be **at least as long** as the file you want to encrypt

## Usage

```
otp E <input> <output>     Encrypt <input> to <output>
otp D <input> <output>     Decrypt <input> to <output>
otp -h | --help | help     Show usage
```

### Examples

```bash
# Encrypt a file
otp E secret.pdf secret.pdf.enc

# Decrypt it later
otp D secret.pdf.enc secret.pdf
```

## How It Works

1. Looks for `key.key` in the same directory as the `otp` executable.
2. Streams the input file, XORing it with the key (in 8 KiB chunks).
3. Writes to a temporary file next to the output.
4. Atomically renames the temp file to the final output name and syncs the directory.
5. On any error, the temporary file is automatically cleaned up.

The resulting `.enc` file is indistinguishable from random data and contains **nothing** except the encrypted bytes.

## Building

```bash
rustc --edition=2021 -o otp main.rs
```

Or integrate into a Cargo project if desired.

## Security Considerations

One-time pad is information-theoretically secure **only when** all of the following are true:

- The key is generated from a truly random source
- The key is **never reused**
- The key is at least as long as the plaintext
- The key remains secret

This tool does **not** generate or manage keys for you. You are responsible for:

- Creating a sufficiently long, high-quality random key
- Using each key **only once**
- Securely distributing and storing the key
- Securely deleting the key after use (e.g. with `shred`)

## Design Philosophy

- **Minimal trusted computing base** — as little code as possible between you and the XOR operation
- **Fail fast and explicitly** — better to error than do something surprising
- **No implicit behavior** — no automatic key generation, no in-place editing, no filename embedding
- **Durability first** — data is synced to disk before the program considers the operation complete

## License

This is a minimal example tool. Use at your own risk. No warranty is provided.

---

*otp — because sometimes the simplest crypto is still the strongest.*