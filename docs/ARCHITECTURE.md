# kryptograf v2 Architecture

This document captures the core design goals and building blocks for the
stream‑oriented rewrite of kryptograf.

## Goals

- Treat encryption and decryption as streaming middleware that can be dropped
  into network pipelines (`io.Reader`, `io.Writer`, `io.ReadWriter`,
  `io.Pipe`).
- Keep the API small and ergonomic so that non-cryptographers can use it
  safely.
- Provide first-class helpers for minting data-encryption keys (DEKs) from a
  long-lived root key. Root keys must never be used directly for payload
  encryption.
- Offer optional compression without forcing application code to manage the
  ordering.
- Ship benchmarks proving overhead compared to raw I/O.

## Package Layout

```
kryptograf/
├── stream        // Encrypting/decrypting Reader/Writer implementations
├── keymgmt       // Root-key handling, DEK minting, PBKDF2 helpers
├── internal/
│   └── chunkio   // Frame encoding helpers shared by stream readers/writers
├── cmd/
│   └── newkey    // CLI helpers; kept minimal for now
└── docs/
    └── ARCHITECTURE.md
```

The root package re-exports top-level constructors (`NewEncryptWriter`,
`NewDecryptReader`, `NewPipe`) to keep onboarding smooth. Subpackages house the
details so they can evolve without breaking the façade.

## Cryptography

- AES-256-GCM is the default authenticated cipher, with pluggable alternatives
  (ChaCha20/Poly1305, per-frame ChaCha20, XChaCha20/Poly1305, per-frame
  XChaCha20, AES-GCM-SIV) provided through
  `cipher.Factory` adapters. Nonce sizes are driven by the descriptor metadata
  and can be set at mint time via `MintDEKWithNonceSize`.
- Each stream negotiation produces a random base nonce sized for the selected
  AEAD. Frames extend this nonce with a monotonically incrementing 32-bit
  counter (big-endian) to avoid reuse.
  to avoid reuse.
- Frames are encoded as:

  ```
  +----------+-----------+------------------+--------------+
  | counter  | payload   | ciphertext bytes | GCM auth tag  |
  | (uint32) | length    |                  | (16 bytes)    |
  |          | (uint32)  |                  |               |
  +----------+-----------+------------------+--------------+
  ```

  `payload length` refers to the plaintext length for the frame; the writer
  stores the length before encryption so the decryptor can size buffers
  efficiently.

- The final frame is marked by a zero-length payload with a valid tag. This
  allows the decryptor to distinguish EOF from truncated data.

## Compression

Compression happens *before* encryption on the write side and *after*
decryption on the read side. The default is opt-in per stream and supports
pluggable adapters: gzip (pooled), Snappy, and LZ4 ship with the repo, and any
codec can be added by implementing `compression.Adapter`. This keeps encrypted
bytes uniformly random and avoids compressing random ciphertext.

## Key Lifecycle

- `keymgmt.GenerateRootKey()` returns a securely generated 32-byte root key.
- Applications derive DEKs via HKDF (`crypto/hkdf`) using the root key as the
  master secret, caller-supplied context bytes as HKDF info, and a fresh
  32-byte salt generated per DEK mint.
- `MintDEK` returns:
  - `Key`: 32-byte AES key for the payload.
  - `Descriptor`: structured metadata containing the salt, HKDF hash, and the
    12-byte base nonce that must accompany encrypted artifacts.
- `ReconstructDEK` takes the root key, descriptor, and the original context
  bytes to reproduce the DEK for decrypting stored data.
- All helpers return zeroed copies when they go out of scope to reduce the risk
  of leaking secrets via long-lived buffers.
- Root keys and descriptors can be persisted inside PEM bundles or protobuf
  blobs via `keymgmt` helpers, avoiding new sidecar objects.
- A unified storage layer (`keymgmt.Load*`) auto-detects PEM vs protobuf data
  and provides `Commit` semantics for files, writers, or in-memory buffers.

## PBKDF2 & Passphrase Helpers

`keymgmt` exposes:

- `GeneratePBKDF2Params()` → secure defaults (600k iterations, 32-byte salt).
- `DeriveKeyFromPassphrase(passphrase, params...)` → root key plus the params used.
- `PromptPassphrase(reader, prompt, writer)` → passphrase bytes with terminal echo disabled when possible.
- `PromptAndDeriveRootKey(reader, prompt, writer, params...)` → one-shot helper returning the key and params.
- `EnsurePBKDF2Params()` → store method ensuring PBKDF2 params exist and are persisted.
- `EncodeKey/Base64` helpers so keys can be stored as text when necessary.

## API Sketch

```go
rootKey := keymgmt.MustGenerateRootKey()
material, err := keymgmt.MintDEK(rootKey, contextBytes)
if err != nil {
	panic(err)
}

encr, err := stream.NewEncryptWriter(dst, material, stream.WithGzip())
if err != nil {
	panic(err)
}
decr, err := stream.NewDecryptReader(src, material, stream.WithGzip())
if err != nil {
	panic(err)
}

pr, pw, err := stream.NewEncryptPipe(material, stream.WithGzip())
if err != nil {
	panic(err)
}
```

The root package wraps these building blocks:

```go
kg := kryptograf.New(rootKey).WithGzip()
mat, err := kg.MintDEK(contextBytes)
if err != nil {
	panic(err)
}
writer, err := kg.EncryptWriter(dst, mat)
if err != nil {
	panic(err)
}
reader, err := kg.DecryptReader(src, mat)
if err != nil {
	panic(err)
}
```

## Benchmarks

Benchmarks will live alongside the stream package and cover:

- Raw copy throughput (`io.CopyBuffer` baseline).
- Encrypt-only `EncryptWriter`.
- Gzip + encrypt stacked writer.
- Decrypt-only reader.
- Gzip + decrypt reader.

Each benchmark reports MiB/s for realistic payload sizes (1 MiB, 32 MiB) so the
project can demonstrate overhead clearly.

## Testing

- Table-driven unit tests for framing, nonce handling, gzip integration, and
  DEK reconstruction.
- Fuzz tests on decryptors to ensure malformed frames fail gracefully.
- Property tests verifying that round-tripping through encrypt/decrypt yields
  the original data across varying buffer sizes.
