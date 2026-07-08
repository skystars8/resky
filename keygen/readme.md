# Deterministic Key Generator

A simple command-line utility written in Rust that generates deterministic binary key files of any size from **1 byte up to 20 GiB**.

The generated key is completely determined by the password you enter. Entering the same password again with the same version of the program will always produce the exact same key file, byte for byte.

---

## Features

* Deterministic output
* Generates files from **1 byte** to **20 GiB**
* Cryptographically strong output using **BLAKE3 XOF**
* Streams data directly to disk (low memory usage)
* Refuses to overwrite an existing `key.key`
* Password confirmation to prevent typing mistakes
* Works entirely offline

---

## How It Works

The program asks for:

1. The desired key size in bytes.
2. A password.
3. The password again for confirmation.

The password is hashed with BLAKE3 and used to initialize BLAKE3's extendable output function (XOF). The XOF produces a deterministic cryptographic byte stream that is written directly to `key.key`.

Because the stream is deterministic:

* Same password → identical key
* Different password → completely different key

The output is streamed, so generating very large files does not require large amounts of RAM.

---

## Security Properties

The generated key file is binary data.

Every byte may have any value from:

* `0x00`
* through
* `0xFF`

The output is **not text** and is **not limited to printable ASCII characters**.

Unlike simply repeating a hash over and over, the BLAKE3 XOF produces a continuous cryptographic stream that does not repeat a short pattern to fill the requested file size.

---

## Building

Install Rust 1.96 (Edition 2024) or newer.

Clone the project and build:

```bash
cargo build --release
```

---

## Usage

Run the program:

```bash
cargo run --release -- <size_in-bytes>
```

Example:

Generate a 1 MiB key:

```bash
cargo run --release -- 1048576
```

Generate a 1 GiB key:

```bash
cargo run --release -- 1073741824
```

The generated file will be named:

```
key.key
```

If `key.key` already exists, the program will stop rather than overwrite it.

---

## Examples

```
$ cargo run --release -- 1024

Password:
Confirm:

Created key.key (1024 bytes)
```

---

## Memory Usage

The program writes the file in small chunks.

Even when generating a 20 GiB key, memory usage remains approximately 1 MiB.

---

## Deterministic Behavior

Suppose your password is:

```
correct horse battery staple
```

Generating a 100-byte key today and generating it again years later with the same version of the program and the same password will produce exactly the same 100 bytes.

Changing even a single character in the password results in a completely different key.

---

## Limitations

* Passwords are case-sensitive.
* An empty password is not allowed.
* The maximum supported size is 20 GiB.
* Existing `key.key` files are never overwritten.

---

## License

Use at your own risk. No warranty is provided.
