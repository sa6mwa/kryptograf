package kryptograf

import (
	"fmt"
	"io"
	"sync"

	"pkt.systems/kryptograf/cipher"
	"pkt.systems/kryptograf/compression"
	"pkt.systems/kryptograf/keymgmt"
	"pkt.systems/kryptograf/stream"
)

// RootKey re-exports keymgmt.RootKey for convenience.
type RootKey = keymgmt.RootKey

// DEK re-exports keymgmt.DEK.
type DEK = keymgmt.DEK

// Descriptor re-exports keymgmt.Descriptor.
type Descriptor = keymgmt.Descriptor

// StreamOption configures streaming encryptors and decryptors.
type StreamOption = stream.Option

// WithChunkSize forwards to stream.WithChunkSize.
func WithChunkSize(n int) StreamOption { return stream.WithChunkSize(n) }

// WithGzip forwards to stream.WithGzip.
func WithGzip() StreamOption { return stream.WithGzip() }

// WithSnappy forwards to stream.WithSnappy.
func WithSnappy() StreamOption { return stream.WithSnappy() }

// WithLZ4 forwards to stream.WithLZ4.
func WithLZ4() StreamOption { return stream.WithLZ4() }

// WithCompression forwards to stream.WithCompression.
func WithCompression(adapter compression.Adapter) StreamOption {
	return stream.WithCompression(adapter)
}

// WithBufferPool forwards to stream.WithBufferPool.
func WithBufferPool(pool *sync.Pool) StreamOption { return stream.WithBufferPool(pool) }

// WithCipher forwards to stream.WithCipher.
func WithCipher(factory cipher.Factory) StreamOption { return stream.WithCipher(factory) }

// CipherFactory re-exports cipher.Factory for convenience.
type CipherFactory = cipher.Factory

// Kryptograf exposes the high-level streaming API.
type Kryptograf interface {
	// WithOptions appends the provided stream options and returns a Kryptograf that applies them.
	WithOptions(opts ...StreamOption) Kryptograf
	// WithChunkSize returns a Kryptograf configured to use chunked IO with the provided size in bytes.
	WithChunkSize(n int) Kryptograf
	// WithGzip returns a Kryptograf that applies gzip compression to payloads.
	WithGzip() Kryptograf
	// WithSnappy returns a Kryptograf that applies Snappy compression to payloads.
	WithSnappy() Kryptograf
	// WithLZ4 returns a Kryptograf that applies LZ4 compression to payloads.
	WithLZ4() Kryptograf
	// WithCompression returns a Kryptograf that applies the supplied compression adapter when streaming.
	WithCompression(adapter compression.Adapter) Kryptograf
	// WithCipher returns a Kryptograf that encrypts using the supplied cipher factory.
	WithCipher(factory cipher.Factory) Kryptograf
	// RootKey reveals the underlying root key used to mint derived keys.
	RootKey() keymgmt.RootKey
	// MintDEK produces encryption material bound to the provided context bytes.
	MintDEK(context []byte) (Material, error)
	// MintDEKWithNonceSize produces encryption material with a fixed nonce size.
	MintDEKWithNonceSize(context []byte, nonceSize int) (Material, error)
	// ReconstructDEK rebuilds material for an existing descriptor and context.
	ReconstructDEK(context []byte, desc keymgmt.Descriptor) (Material, error)
	// EncryptWriter returns a write-closer that encrypts data into dst.
	EncryptWriter(dst io.Writer, mat Material, opts ...StreamOption) (io.WriteCloser, error)
	// DecryptReader returns a read-closer that decrypts data from src.
	DecryptReader(src io.Reader, mat Material, opts ...StreamOption) (io.ReadCloser, error)
	// NewEncryptPipe yields a ciphertext reader and plaintext writer pair for streaming encryption.
	NewEncryptPipe(mat Material, opts ...StreamOption) (*io.PipeReader, io.WriteCloser, error)
	// NewDecryptPipe yields a plaintext reader and ciphertext writer pair for streaming decryption.
	NewDecryptPipe(mat Material, opts ...StreamOption) (io.ReadCloser, *io.PipeWriter, error)
}

type service struct {
	root       keymgmt.RootKey
	streamOpts []StreamOption
}

// Material bundles a DEK with its descriptor.
type Material = keymgmt.Material

// New constructs a Kryptograf instance with default configuration.
func New(root keymgmt.RootKey) Kryptograf {
	return &service{root: root}
}

// WithOptions appends arbitrary stream options and returns the receiver for chaining.
func (s *service) WithOptions(opts ...StreamOption) Kryptograf {
	s.streamOpts = append(s.streamOpts, opts...)
	return s
}

// WithChunkSize adds a chunk-size option to the configuration.
func (s *service) WithChunkSize(n int) Kryptograf {
	return s.WithOptions(WithChunkSize(n))
}

// WithGzip enables gzip compression for the instance.
func (s *service) WithGzip() Kryptograf {
	return s.WithOptions(WithGzip())
}

// WithSnappy enables Snappy compression for the instance.
func (s *service) WithSnappy() Kryptograf {
	return s.WithOptions(WithSnappy())
}

// WithLZ4 enables LZ4 compression for the instance.
func (s *service) WithLZ4() Kryptograf {
	return s.WithOptions(WithLZ4())
}

// WithCompression selects the compression adapter for the instance.
func (s *service) WithCompression(adapter compression.Adapter) Kryptograf {
	return s.WithOptions(WithCompression(adapter))
}

// WithCipher selects the cipher implementation for the instance.
func (s *service) WithCipher(factory cipher.Factory) Kryptograf {
	return s.WithOptions(WithCipher(factory))
}

// RootKey returns a copy of the underlying root key.
func (s *service) RootKey() keymgmt.RootKey {
	return s.root
}

// MintDEK derives a new DEK bound to the supplied context bytes.
func (s *service) MintDEK(context []byte) (Material, error) {
	return keymgmt.MintDEK(s.root, context)
}

// MintDEKWithNonceSize derives a DEK with a specific nonce size for downstream ciphers.
func (s *service) MintDEKWithNonceSize(context []byte, nonceSize int) (Material, error) {
	return keymgmt.MintDEKWithNonceSize(s.root, context, nonceSize)
}

// ReconstructDEK rebuilds the DEK for an existing descriptor.
func (s *service) ReconstructDEK(context []byte, desc keymgmt.Descriptor) (Material, error) {
	return keymgmt.ReconstructMaterial(s.root, context, desc)
}

// EncryptWriter wraps dst with an AES-GCM streaming encryptor.
func (s *service) EncryptWriter(dst io.Writer, mat Material, opts ...StreamOption) (io.WriteCloser, error) {
	if mat.Key == (keymgmt.DEK{}) {
		return nil, fmt.Errorf("kryptograf: material key is empty")
	}
	return stream.NewEncryptWriter(dst, mat, s.merge(opts)...)
}

// DecryptReader wraps src with an AES-GCM streaming decryptor.
func (s *service) DecryptReader(src io.Reader, mat Material, opts ...StreamOption) (io.ReadCloser, error) {
	if mat.Key == (keymgmt.DEK{}) {
		return nil, fmt.Errorf("kryptograf: material key is empty")
	}
	return stream.NewDecryptReader(src, mat, s.merge(opts)...)
}

// NewEncryptPipe returns an io.Pipe reader for ciphertext and a writer for plaintext.
func (s *service) NewEncryptPipe(mat Material, opts ...StreamOption) (*io.PipeReader, io.WriteCloser, error) {
	if mat.Key == (keymgmt.DEK{}) {
		return nil, nil, fmt.Errorf("kryptograf: material key is empty")
	}
	return stream.NewEncryptPipe(mat, s.merge(opts)...)
}

// NewDecryptPipe returns a plaintext reader and a writer that accepts ciphertext.
func (s *service) NewDecryptPipe(mat Material, opts ...StreamOption) (io.ReadCloser, *io.PipeWriter, error) {
	if mat.Key == (keymgmt.DEK{}) {
		return nil, nil, fmt.Errorf("kryptograf: material key is empty")
	}
	return stream.NewDecryptPipe(mat, s.merge(opts)...)
}

func (s *service) merge(opts []StreamOption) []StreamOption {
	if len(s.streamOpts) == 0 {
		return opts
	}
	merged := make([]StreamOption, 0, len(s.streamOpts)+len(opts))
	merged = append(merged, s.streamOpts...)
	merged = append(merged, opts...)
	return merged
}

// GenerateRootKey re-exports keymgmt.GenerateRootKey.
func GenerateRootKey() (RootKey, error) {
	return keymgmt.GenerateRootKey()
}

// MustGenerateRootKey re-exports keymgmt.MustGenerateRootKey.
func MustGenerateRootKey() RootKey {
	return keymgmt.MustGenerateRootKey()
}

// RootKeyFromBase64 decodes a base64 (raw, URL-safe) encoded string into a
// RootKey.
func RootKeyFromBase64(encoded string) (RootKey, error) {
	return keymgmt.RootKeyFromBase64(encoded)
}

// RootKeyFromHex decodes a hex string into a RootKey.
func RootKeyFromHex(encoded string) (RootKey, error) {
	return keymgmt.RootKeyFromHex(encoded)
}

// RootKeyFromBytes copies b into a RootKey. Returns an error if b does not
// contain exactly 32 bytes.
func RootKeyFromBytes(b []byte) (RootKey, error) {
	return keymgmt.RootKeyFromBytes(b)
}

// MintDEK re-exports keymgmt.MintDEK for convenience.
func MintDEK(root RootKey, context []byte) (Material, error) {
	return keymgmt.MintDEK(root, context)
}

// MintDEKWithNonceSize re-exports keymgmt.MintDEKWithNonceSize.
func MintDEKWithNonceSize(root RootKey, context []byte, nonceSize int) (Material, error) {
	return keymgmt.MintDEKWithNonceSize(root, context, nonceSize)
}

// ReconstructDEK re-exports keymgmt.ReconstructDEK for convenience.
func ReconstructDEK(root RootKey, context []byte, desc Descriptor) (DEK, error) {
	return keymgmt.ReconstructDEK(root, context, desc)
}

// ReconstructMaterial re-exports keymgmt.ReconstructMaterial for convenience.
func ReconstructMaterial(root RootKey, context []byte, desc Descriptor) (Material, error) {
	return keymgmt.ReconstructMaterial(root, context, desc)
}

// Load re-exports keymgmt.Load for convenience.
func Load(from any) (keymgmt.Store, error) {
	return keymgmt.Load(from)
}

// LoadInto re-exports keymgmt.LoadInto for convenience.
func LoadInto(from any, to any) (keymgmt.Store, error) {
	return keymgmt.LoadInto(from, to)
}

// LoadPEM re-exports keymgmt.LoadPEM for convenience.
func LoadPEM(from any) (keymgmt.Store, error) {
	return keymgmt.LoadPEM(from)
}

// LoadProto re-exports keymgmt.LoadProto for convenience.
func LoadProto(from any) (keymgmt.Store, error) {
	return keymgmt.LoadProto(from)
}

// EnsureRootKey delegates to the store's EnsureRootKey helper.
func EnsureRootKey(store keymgmt.Store) (RootKey, error) {
	return store.EnsureRootKey()
}

// EnsureDescriptor delegates to the store's EnsureDescriptor helper.
func EnsureDescriptor(store keymgmt.Store, name string, root RootKey, context []byte) (Material, error) {
	return store.EnsureDescriptor(name, root, context)
}

// EnsurePBKDF2Params delegates to the store's EnsurePBKDF2Params helper.
func EnsurePBKDF2Params(store keymgmt.Store) (keymgmt.PBKDF2Params, error) {
	return store.EnsurePBKDF2Params()
}

// GeneratePBKDF2Params re-exports keymgmt.GeneratePBKDF2Params.
func GeneratePBKDF2Params() (keymgmt.PBKDF2Params, error) {
	return keymgmt.GeneratePBKDF2Params()
}

// MustGeneratePBKDF2Params re-exports keymgmt.MustGeneratePBKDF2Params.
func MustGeneratePBKDF2Params() keymgmt.PBKDF2Params {
	return keymgmt.MustGeneratePBKDF2Params()
}

// PromptAndDeriveRootKey re-exports keymgmt.PromptAndDeriveRootKey, allowing
// optional PBKDF2 parameters and returning the parameters applied.
func PromptAndDeriveRootKey(r io.Reader, prompt string, w io.Writer, params ...keymgmt.PBKDF2Params) (keymgmt.RootKey, keymgmt.PBKDF2Params, error) {
	return keymgmt.PromptAndDeriveRootKey(r, prompt, w, params...)
}

// DeriveKeyFromPassphrase derives a RootKey using PBKDF2, applying secure
// defaults when no parameters are provided. The parameters used are returned
// alongside the key.
func DeriveKeyFromPassphrase(passphrase []byte, params ...keymgmt.PBKDF2Params) (keymgmt.RootKey, keymgmt.PBKDF2Params, error) {
	return keymgmt.DeriveKeyFromPassphrase(passphrase, params...)
}

// MarshalPBKDF2Params re-exports keymgmt.MarshalPBKDF2Params.
func MarshalPBKDF2Params(params keymgmt.PBKDF2Params) ([]byte, error) {
	return keymgmt.MarshalPBKDF2Params(params)
}

// UnmarshalPBKDF2Params re-exports keymgmt.UnmarshalPBKDF2Params.
func UnmarshalPBKDF2Params(data []byte) (keymgmt.PBKDF2Params, error) {
	return keymgmt.UnmarshalPBKDF2Params(data)
}
