package stream

import (
	"fmt"
	"sync"

	"pkt.systems/kryptograf/cipher"
	"pkt.systems/kryptograf/compression"
)

type config struct {
	chunkSize     int
	compressor    compression.Adapter
	cipherFactory cipher.Factory
	bufferPool    *sync.Pool
}

const (
	defaultChunkSize = 64 * 1024
	minChunkSize     = 1024
)

// Option configures the behaviour of encrypting/decrypting streams.
type Option func(*config)

func applyOptions(opts []Option) config {
	cfg := config{
		chunkSize:     defaultChunkSize,
		cipherFactory: cipher.AESGCM(),
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// WithChunkSize controls the size of plaintext chunks that are sealed in a
// single AES-GCM frame. Larger chunk sizes reduce framing overhead but increase
// buffering requirements.
func WithChunkSize(n int) Option {
	return func(cfg *config) {
		if n < minChunkSize {
			panic(fmt.Sprintf("kryptograf/stream: chunk size must be >= %d", minChunkSize))
		}
		cfg.chunkSize = n
	}
}

// WithBufferPool allows callers to share chunk buffers across encrypt/decrypt
// streams to reduce allocations. The pool should store *bufferSet values. The
// pooled buffers are zeroed before being returned. Passing nil leaves pooling
// disabled.
func WithBufferPool(pool *sync.Pool) Option {
	return func(cfg *config) {
		cfg.bufferPool = pool
	}
}

// WithCompression selects the compression adapter used before encryption and after decryption.
func WithCompression(adapter compression.Adapter) Option {
	return func(cfg *config) {
		cfg.compressor = adapter
	}
}

// WithGzip enables gzip compression using a pooled writer.
func WithGzip() Option {
	return WithCompression(compression.GzipDefault())
}

// WithSnappy enables Snappy compression using pooled readers/writers.
func WithSnappy() Option {
	return WithCompression(compression.Snappy())
}

// WithLZ4 enables LZ4 compression using pooled readers/writers.
func WithLZ4() Option {
	return WithCompression(compression.LZ4())
}

// WithCipher selects the cipher implementation used for sealing frames.
func WithCipher(factory cipher.Factory) Option {
	return func(cfg *config) {
		cfg.cipherFactory = factory
	}
}
