package stream

import (
	"errors"
	"fmt"
	"io"
	"slices"

	"pkt.systems/kryptograf/cipher"
	"pkt.systems/kryptograf/internal/chunkio"
	"pkt.systems/kryptograf/keymgmt"
)

var (
	errWriterClosed = errors.New("kryptograf/stream: writer already closed")
)

// NewEncryptWriter creates an io.WriteCloser that encrypts all plaintext
// written to it using the supplied material.
func NewEncryptWriter(dst io.Writer, material keymgmt.Material, opts ...Option) (io.WriteCloser, error) {
	cfg := applyOptions(opts)
	crypt, err := cfg.cipherFactory(material.Key.Bytes())
	if err != nil {
		return nil, fmt.Errorf("stream encrypt writer: %w", err)
	}

	descCopy := material.Descriptor
	if err := (&descCopy).Validate(); err != nil {
		return nil, err
	}
	noncePrefix := descCopy.NoncePrefix()
	if len(noncePrefix) != crypt.NonceSize() {
		return nil, fmt.Errorf("stream encrypt writer: cipher nonce size %d does not match descriptor size %d", crypt.NonceSize(), len(noncePrefix))
	}

	w := &writer{
		dst:        dst,
		cipher:     crypt,
		nonceBase:  slices.Clone(noncePrefix),
		nonceBuf:   make([]byte, len(noncePrefix)),
		chunkSize:  cfg.chunkSize,
		headerBuf:  make([]byte, chunkio.FrameHeaderSize),
		closer:     toCloser(dst),
		overhead:   crypt.Overhead(),
		plaintext:  make([]byte, 0, cfg.chunkSize),
		ciphertext: make([]byte, 0, cfg.chunkSize+int(crypt.Overhead())),
	}

	if cfg.compressor != nil {
		comp, err := cfg.compressor.WrapWriter(&plainSink{w: w})
		if err != nil {
			return nil, fmt.Errorf("stream encrypt writer: %w", err)
		}
		w.compressor = comp
	}

	return w, nil
}

type writer struct {
	dst        io.Writer
	cipher     cipher.Cipher
	nonceBase  []byte
	nonceBuf   []byte
	counter    uint32
	chunkSize  int
	headerBuf  []byte
	plaintext  []byte
	ciphertext []byte
	overhead   int
	closer     io.Closer
	closed     bool

	compressor io.WriteCloser
}

func (w *writer) Write(p []byte) (int, error) {
	if w.compressor != nil {
		return w.compressor.Write(p)
	}
	return w.writePlain(p)
}

func (w *writer) writePlain(p []byte) (int, error) {
	if w.closed {
		return 0, errWriterClosed
	}
	written := 0

	if len(w.plaintext) > 0 {
		space := w.chunkSize - len(w.plaintext)
		if space > len(p) {
			w.plaintext = append(w.plaintext, p...)
			return len(p), nil
		}
		w.plaintext = append(w.plaintext, p[:space]...)
		if err := w.emitChunk(w.plaintext, false); err != nil {
			return written, err
		}
		written += space
		w.plaintext = w.plaintext[:0]
		p = p[space:]
	}

	for len(p) >= w.chunkSize {
		if err := w.emitChunk(p[:w.chunkSize], false); err != nil {
			return written, err
		}
		p = p[w.chunkSize:]
		written += w.chunkSize
	}

	if len(p) > 0 {
		w.plaintext = append(w.plaintext, p...)
		written += len(p)
	}
	return written, nil
}

func (w *writer) Close() error {
	if w.closed {
		return nil
	}

	if w.compressor != nil {
		if err := w.compressor.Close(); err != nil {
			return fmt.Errorf("close compressor: %w", err)
		}
		w.compressor = nil
	}

	if len(w.plaintext) > 0 {
		if err := w.emitChunk(w.plaintext, false); err != nil {
			return err
		}
		w.plaintext = w.plaintext[:0]
	}

	if err := w.emitChunk(nil, true); err != nil {
		return err
	}

	w.closed = true

	if w.closer != nil {
		if err := w.closer.Close(); err != nil {
			return fmt.Errorf("close destination: %w", err)
		}
	}
	return nil
}

func (w *writer) emitChunk(plaintext []byte, final bool) error {
	if final {
		// final frame must have zero-length plaintext
		plaintext = plaintext[:0]
	}

	if !final && len(plaintext) == 0 {
		return nil
	}

	payloadLen := len(plaintext)
	var header chunkio.Header
	header.Version = chunkio.FrameVersion()
	header.Counter = w.counter
	header.Payload = uint32(payloadLen)
	if final {
		chunkio.MarkFinal(&header)
	}

	if err := chunkio.DeriveNonce(w.nonceBuf, w.nonceBase, w.counter); err != nil {
		return err
	}

	chunkio.EncodeHeader(w.headerBuf, header)

	ciphertext := w.ciphertext[:0]
	if cap(ciphertext) < payloadLen+w.overhead {
		w.ciphertext = make([]byte, 0, payloadLen+w.overhead)
		ciphertext = w.ciphertext
	}
	ciphertext, sealErr := w.cipher.Seal(ciphertext[:0], w.nonceBuf, plaintext, nil)
	if sealErr != nil {
		return sealErr
	}

	if err := writeFull(w.dst, w.headerBuf); err != nil {
		return err
	}
	if err := writeFull(w.dst, ciphertext); err != nil {
		return err
	}

	if final {
		return nil
	}

	next, err := chunkio.NextCounter(w.counter)
	if err != nil {
		return err
	}
	w.counter = next
	return nil
}

type plainSink struct {
	w *writer
}

func (p *plainSink) Write(b []byte) (int, error) {
	return p.w.writePlain(b)
}

func writeFull(w io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}
	return nil
}
