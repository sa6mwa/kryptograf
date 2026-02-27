package stream

import (
	"fmt"
	"sync"

	"pkt.systems/kryptograf/cipher"
	"pkt.systems/kryptograf/compression"
)

type config struct {
	chunkSize            int
	compressor           compression.Adapter
	cipherFactory        cipher.Factory
	bufferPool           *sync.Pool
	sourceReadBufferSize int
	sourceReadBufferPool *sync.Pool
}

const (
	defaultChunkSize        = 64 * 1024
	minChunkSize            = 1024
	minSourceReadBufferSize = 1024
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

// WithSourceReadBuffer controls decrypt source read buffering in bytes.
// Source buffering is disabled by default. Set n > 0 to enable source
// buffering; set n to 0 to disable it explicitly. Values from 1 to 1023 panic.
func WithSourceReadBuffer(n int) Option {
	return func(cfg *config) {
		if n < 0 {
			panic("kryptograf/stream: source read buffer size must be >= 0")
		}
		if n > 0 && n < minSourceReadBufferSize {
			panic(fmt.Sprintf("kryptograf/stream: source read buffer size must be >= %d or 0 to disable", minSourceReadBufferSize))
		}
		cfg.sourceReadBufferSize = n
	}
}

// WithSourceReadBufferPool lets decrypt readers reuse buffered source reader
// instances and avoid per-reader buffer churn. The pool should store
// *bufio.Reader values sized for the chosen source buffer size. Readers are
// reset before being put back and are owned by decrypt reader instances while
// in use. Passing nil leaves custom pooling disabled; built-in pools are used
// for common sizes (8/16/32/64 KiB).
func WithSourceReadBufferPool(pool *sync.Pool) Option {
	return func(cfg *config) {
		cfg.sourceReadBufferPool = pool
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
