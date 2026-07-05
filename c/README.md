# otp — Minimal OTP-Style XOR File Processor

A tiny, strict, Linux-focused tool that encrypts and decrypts files using XOR with a one-time pad (`key.key`).

**The key insight:** because XOR is its own inverse, there is no separate "encrypt" and "decrypt" mode.  
Running the tool once turns plaintext into ciphertext. Running it again on the ciphertext with the same key recovers the original file.

## Features

- Extremely small trusted code base
- No headers, magic numbers, or metadata in the output — the encrypted file contains *only* the XORed bytes
- Atomic writes (temp file + rename) so you never end up with a partial/corrupt output
- `fsync` + directory sync for durability
- Streaming implementation — constant memory usage even for huge files
- Buffers are zeroized after use
- Single, simple command: `otp <input> <output>`

## Why This Design?

Modern authenticated encryption (AES-GCM, ChaCha20-Poly1305, etc.) is almost always the right choice.  
This tool exists for very specific situations where you want classic one-time-pad semantics and are willing to manage a truly random key that is at least as large as the data you want to protect.

It is intentionally minimal and auditable.

## Building

```bash
cargo build --release
```

The resulting binary is `target/release/otp`.

## Usage

```bash
otp <input> <output>
```

### Examples

Encrypt a file:
```bash
otp secret.pdf secret.pdf.enc
```

Decrypt it again (same command, reversed files):
```bash
otp secret.pdf.enc secret.pdf
```

The tool will refuse to run if:
- `input` and `output` are the same path
- `input` does not exist or is not a regular file
- `output` already exists
- `key.key` is smaller than the input file

## The Key File

The program looks for a file named `key.key` in the **same directory as the executable**.

- It must be at least as large as the file you are processing.
- Any extra bytes in the key are simply ignored.
- For real security you should use high-quality random data (e.g. from `/dev/urandom` or a hardware RNG) and **never reuse** the key for more than one message.

Example key generation (creates a 1 MiB key):
```bash
dd if=/dev/urandom of=key.key bs=1M count=1
```

## Security Notes & Limitations

- This is a **raw one-time pad**. It provides perfect secrecy **only** if:
  - The key is truly random
  - The key is at least as long as the plaintext
  - The key is never reused
- There is **no authentication**. An attacker who can flip bits in the ciphertext can flip the corresponding bits in the plaintext after decryption.
- The tool makes no attempt to hide file sizes or metadata.
- It is **not** a replacement for age, gpg, or modern AEAD libraries for most use cases.

Use this tool when you specifically want OTP properties and are prepared to handle the key-management requirements.

## Technical Details

- Written in safe Rust
- Streaming XOR in 8 KiB chunks
- Uses a RAII guard (`TempPath`) to automatically clean up temporary files on error or panic
- Performs `fsync` on the output file and its parent directory before reporting success
- All sensitive buffers are explicitly zeroized before being dropped

## License

MIT

---

Made with care for minimalism and correctness.