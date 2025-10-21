package stream

import (
	"errors"
	"fmt"
	"io"
	"slices"

	"pkt.systems/kryptograf/cipher"
	"pkt.systems/kryptograf/compression"
	"pkt.systems/kryptograf/internal/chunkio"
	"pkt.systems/kryptograf/keymgmt"
)

var (
	errUnexpectedFinalFrame = errors.New("kryptograf/stream: unexpected final frame payload")
)

// NewDecryptReader creates an io.ReadCloser that yields plaintext read from src.
// The supplied material must originate from the same minting process (or the
// descriptor must have been persisted and the key reconstructed).
func NewDecryptReader(src io.Reader, material keymgmt.Material, opts ...Option) (io.ReadCloser, error) {
	descCopy := material.Descriptor
	if err := (&descCopy).Validate(); err != nil {
		return nil, err
	}
	cfg := applyOptions(opts)
	crypt, err := cfg.cipherFactory(material.Key.Bytes())
	if err != nil {
		return nil, fmt.Errorf("stream decrypt reader: %w", err)
	}
	noncePrefix := descCopy.NoncePrefix()
	if len(noncePrefix) != crypt.NonceSize() {
		return nil, fmt.Errorf("stream decrypt reader: cipher nonce size %d does not match descriptor size %d", crypt.NonceSize(), len(noncePrefix))
	}

	r := &reader{
		src:        src,
		cipher:     crypt,
		nonceBase:  slices.Clone(noncePrefix),
		nonceBuf:   make([]byte, len(noncePrefix)),
		headerBuf:  make([]byte, chunkio.FrameHeaderSize),
		overhead:   crypt.Overhead(),
		closer:     toCloser(src),
		ciphertext: make([]byte, 0, cfg.chunkSize+crypt.Overhead()),
		plaintext:  make([]byte, 0, cfg.chunkSize),
	}

	if cfg.compressor != nil {
		return &lazyCompressionReader{adapter: cfg.compressor, base: r}, nil
	}

	return r, nil
}

type reader struct {
	src        io.Reader
	cipher     cipher.Cipher
	nonceBase  []byte
	nonceBuf   []byte
	counter    uint32
	headerBuf  []byte
	ciphertext []byte
	plaintext  []byte
	offset     int
	overhead   int
	finalSeen  bool
	closer     io.Closer
}

func (r *reader) Read(p []byte) (int, error) {
	for r.offset == len(r.plaintext) {
		if r.finalSeen {
			return 0, io.EOF
		}
		if err := r.fill(); err != nil {
			if errors.Is(err, io.EOF) {
				return 0, io.EOF
			}
			return 0, err
		}
	}

	n := copy(p, r.plaintext[r.offset:])
	r.offset += n
	return n, nil
}

func (r *reader) fill() error {
	if _, err := io.ReadFull(r.src, r.headerBuf); err != nil {
		return err
	}

	header, err := chunkio.DecodeHeader(r.headerBuf)
	if err != nil {
		return err
	}

	if header.Counter != r.counter {
		return chunkio.ErrCounterMismatch
	}

	payloadLen := int(header.Payload)
	totalLen := payloadLen + r.overhead
	if cap(r.ciphertext) < totalLen {
		r.ciphertext = make([]byte, totalLen)
	}
	r.ciphertext = r.ciphertext[:totalLen]

	if _, err := io.ReadFull(r.src, r.ciphertext); err != nil {
		return err
	}

	if err := chunkio.DeriveNonce(r.nonceBuf, r.nonceBase, r.counter); err != nil {
		return err
	}

	if cap(r.plaintext) < payloadLen {
		r.plaintext = make([]byte, payloadLen)
	} else {
		r.plaintext = r.plaintext[:payloadLen]
	}

	plain, err := r.cipher.Open(r.plaintext[:0], r.nonceBuf, r.ciphertext, nil)
	if err != nil {
		return err
	}

	if chunkio.FinalFlag(header) {
		if len(plain) != 0 || payloadLen != 0 {
			return errUnexpectedFinalFrame
		}
		r.finalSeen = true
		r.plaintext = r.plaintext[:0]
		r.offset = 0
		return io.EOF
	}

	r.plaintext = plain
	r.offset = 0

	next, err := chunkio.NextCounter(r.counter)
	if err != nil {
		return err
	}
	r.counter = next
	return nil
}

func (r *reader) Close() error {
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}

type lazyCompressionReader struct {
	adapter compression.Adapter
	base    io.ReadCloser
	rc      io.ReadCloser
}

func (l *lazyCompressionReader) ensure() error {
	if l.rc != nil {
		return nil
	}
	rc, err := l.adapter.WrapReader(l.base)
	if err != nil {
		return err
	}
	l.rc = rc
	return nil
}

func (l *lazyCompressionReader) Read(p []byte) (int, error) {
	if err := l.ensure(); err != nil {
		return 0, err
	}
	return l.rc.Read(p)
}

func (l *lazyCompressionReader) Close() error {
	if l.rc != nil {
		_ = l.rc.Close()
	}
	if l.base != nil {
		return l.base.Close()
	}
	return nil
}
