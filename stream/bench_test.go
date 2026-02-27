package stream

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"sync"
	"testing"

	"pkt.systems/kryptograf/cipher"
	"pkt.systems/kryptograf/keymgmt"
)

var benchPayload = bytes.Repeat([]byte("kryptograf-streaming-benchmark-"), 1<<12) // ~124 KiB

func BenchmarkCopy(b *testing.B) {
	buf := make([]byte, 64*1024)
	for b.Loop() {
		reader := bytes.NewReader(benchPayload)
		if _, err := io.CopyBuffer(io.Discard, reader, buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	root, _ := keymgmt.GenerateRootKey()
	mat, _ := keymgmt.MintDEK(root, []byte("benchmark-encrypt"))
	for b.Loop() {
		descCopy := mat.Descriptor
		if _, err := rand.Read(descCopy.Nonce[:8]); err != nil {
			b.Fatal(err)
		}
		var out bytes.Buffer
		w, err := NewEncryptWriter(&out, keymgmt.Material{Key: mat.Key, Descriptor: descCopy})
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(w, bytes.NewReader(benchPayload)); err != nil {
			b.Fatal(err)
		}
		if err := w.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptGzip(b *testing.B) {
	root, _ := keymgmt.GenerateRootKey()
	mat, _ := keymgmt.MintDEK(root, []byte("benchmark-encrypt-gzip"))
	for b.Loop() {
		descCopy := mat.Descriptor
		if _, err := rand.Read(descCopy.Nonce[:8]); err != nil {
			b.Fatal(err)
		}
		var out bytes.Buffer
		w, err := NewEncryptWriter(&out, keymgmt.Material{Key: mat.Key, Descriptor: descCopy}, WithGzip())
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(w, bytes.NewReader(benchPayload)); err != nil {
			b.Fatal(err)
		}
		if err := w.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptChaCha20Poly1305(b *testing.B) {
	root, _ := keymgmt.GenerateRootKey()
	mat, _ := keymgmt.MintDEK(root, []byte("benchmark-encrypt-chacha"))
	factory := cipher.ChaCha20Poly1305()

	for b.Loop() {
		descCopy := mat.Descriptor
		if _, err := rand.Read(descCopy.Nonce[:8]); err != nil {
			b.Fatal(err)
		}
		var out bytes.Buffer
		w, err := NewEncryptWriter(&out, keymgmt.Material{Key: mat.Key, Descriptor: descCopy}, WithCipher(factory))
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(w, bytes.NewReader(benchPayload)); err != nil {
			b.Fatal(err)
		}
		if err := w.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	root, _ := keymgmt.GenerateRootKey()
	mat, _ := keymgmt.MintDEK(root, []byte("benchmark-decrypt"))
	var cipherBuf bytes.Buffer
	w, err := NewEncryptWriter(&cipherBuf, mat)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := io.Copy(w, bytes.NewReader(benchPayload)); err != nil {
		b.Fatal(err)
	}
	if err := w.Close(); err != nil {
		b.Fatal(err)
	}
	ciphertext := cipherBuf.Bytes()

	for b.Loop() {
		reader, err := NewDecryptReader(bytes.NewReader(ciphertext), mat)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, reader); err != nil {
			b.Fatal(err)
		}
		reader.Close()
	}
}

func BenchmarkDecryptGzip(b *testing.B) {
	root, _ := keymgmt.GenerateRootKey()
	mat, _ := keymgmt.MintDEK(root, []byte("benchmark-decrypt-gzip"))
	var cipherBuf bytes.Buffer
	w, err := NewEncryptWriter(&cipherBuf, mat, WithGzip())
	if err != nil {
		b.Fatal(err)
	}
	if _, err := io.Copy(w, bytes.NewReader(benchPayload)); err != nil {
		b.Fatal(err)
	}
	if err := w.Close(); err != nil {
		b.Fatal(err)
	}
	ciphertext := cipherBuf.Bytes()

	for b.Loop() {
		reader, err := NewDecryptReader(bytes.NewReader(ciphertext), mat, WithGzip())
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, reader); err != nil {
			b.Fatal(err)
		}
		reader.Close()
	}
}

func BenchmarkDecryptMatrix(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{name: "4KiB", size: 4 * 1024},
		{name: "64KiB", size: 64 * 1024},
		{name: "256KiB", size: 256 * 1024},
		{name: "1MiB", size: 1 * 1024 * 1024},
		{name: "8MiB", size: 8 * 1024 * 1024},
	}

	compressions := []struct {
		name        string
		encryptOpts []Option
		decryptOpts []Option
	}{
		{
			name: "none",
		},
		{
			name:        "snappy",
			encryptOpts: []Option{WithSnappy()},
			decryptOpts: []Option{WithSnappy()},
		},
	}

	policies := []struct {
		name string
		opts func() []Option
	}{
		{
			name: "default",
			opts: func() []Option { return nil },
		},
		{
			name: "source-buffer-disabled",
			opts: func() []Option {
				return []Option{WithSourceReadBuffer(0)}
			},
		},
		{
			name: "source-buffer-forced-8KiB",
			opts: func() []Option {
				return []Option{WithSourceReadBuffer(8 * 1024)}
			},
		},
		{
			name: "source-buffer-forced-16KiB",
			opts: func() []Option {
				return []Option{WithSourceReadBuffer(16 * 1024)}
			},
		},
		{
			name: "source-buffer-forced-64KiB",
			opts: func() []Option {
				return []Option{WithSourceReadBuffer(64 * 1024)}
			},
		},
		{
			name: "source-buffer-forced-64KiB-pooled",
			opts: func() []Option {
				var pool sync.Pool
				pool.Put(bufio.NewReaderSize(bytes.NewReader(nil), 64*1024))
				return []Option{
					WithSourceReadBuffer(64 * 1024),
					WithSourceReadBufferPool(&pool),
				}
			},
		},
	}

	root, _ := keymgmt.GenerateRootKey()

	for _, sz := range sizes {
		sz := sz
		payload := makeBenchPayload(sz.size)
		b.Run(sz.name, func(b *testing.B) {
			b.SetBytes(int64(len(payload)))
			for _, comp := range compressions {
				comp := comp
				b.Run(comp.name, func(b *testing.B) {
					mat, _ := keymgmt.MintDEK(root, []byte("benchmark-decrypt-matrix-"+sz.name+"-"+comp.name))
					ciphertext := encryptBenchPayload(b, mat, payload, comp.encryptOpts...)
					cipherFile := writeBenchCipherFile(b, ciphertext)

					sources := []struct {
						name string
						new  func() io.Reader
					}{
						{
							name: "bytes-reader",
							new: func() io.Reader {
								return bytes.NewReader(ciphertext)
							},
						},
						{
							name: "section-reader",
							new: func() io.Reader {
								backing := bytes.NewReader(ciphertext)
								return io.NewSectionReader(backing, 0, int64(len(ciphertext)))
							},
						},
						{
							name: "file-section-reader",
							new: func() io.Reader {
								return io.NewSectionReader(cipherFile, 0, int64(len(ciphertext)))
							},
						},
						{
							name: "fragmented-29B",
							new: func() io.Reader {
								return &benchCappedReader{r: bytes.NewReader(ciphertext), max: 29}
							},
						},
					}

					for _, src := range sources {
						src := src
						b.Run(src.name, func(b *testing.B) {
							for _, pol := range policies {
								pol := pol
								b.Run(pol.name, func(b *testing.B) {
									polOpts := pol.opts()
									opts := make([]Option, 0, len(comp.decryptOpts)+len(polOpts))
									opts = append(opts, comp.decryptOpts...)
									opts = append(opts, polOpts...)
									for b.Loop() {
										reader, err := NewDecryptReader(src.new(), mat, opts...)
										if err != nil {
											b.Fatal(err)
										}
										if _, err := io.Copy(io.Discard, reader); err != nil {
											b.Fatal(err)
										}
										if err := reader.Close(); err != nil {
											b.Fatal(err)
										}
									}
								})
							}
						})
					}
				})
			}
		})
	}
}

func BenchmarkDecryptLarge100MiB(b *testing.B) {
	const payloadSize = int64(100 * 1024 * 1024)

	compressions := []struct {
		name        string
		encryptOpts []Option
		decryptOpts []Option
	}{
		{name: "none"},
		{
			name:        "snappy",
			encryptOpts: []Option{WithSnappy()},
			decryptOpts: []Option{WithSnappy()},
		},
	}

	policies := []struct {
		name string
		opts []Option
	}{
		{
			name: "source-buffer-disabled",
			opts: []Option{WithSourceReadBuffer(0)},
		},
		{
			name: "source-buffer-forced-64KiB",
			opts: []Option{WithSourceReadBuffer(64 * 1024)},
		},
	}

	root, _ := keymgmt.GenerateRootKey()
	for _, comp := range compressions {
		comp := comp
		b.Run(comp.name, func(b *testing.B) {
			mat, _ := keymgmt.MintDEK(root, []byte("benchmark-decrypt-large-100m-"+comp.name))
			cipherFile, cipherSize := writeBenchCipherFileFromStream(b, mat, payloadSize, comp.encryptOpts...)

			b.SetBytes(payloadSize)
			for _, pol := range policies {
				pol := pol
				b.Run(pol.name, func(b *testing.B) {
					opts := make([]Option, 0, len(comp.decryptOpts)+len(pol.opts))
					opts = append(opts, comp.decryptOpts...)
					opts = append(opts, pol.opts...)
					for b.Loop() {
						src := io.NewSectionReader(cipherFile, 0, cipherSize)
						reader, err := NewDecryptReader(src, mat, opts...)
						if err != nil {
							b.Fatal(err)
						}
						if _, err := io.Copy(io.Discard, reader); err != nil {
							b.Fatal(err)
						}
						if err := reader.Close(); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func makeBenchPayload(size int) []byte {
	base := []byte("kryptograf-streaming-benchmark-")
	payload := make([]byte, size)
	for offset := 0; offset < size; offset += len(base) {
		copy(payload[offset:], base)
	}
	return payload
}

func encryptBenchPayload(b *testing.B, mat keymgmt.Material, payload []byte, opts ...Option) []byte {
	b.Helper()
	var cipherBuf bytes.Buffer
	w, err := NewEncryptWriter(&cipherBuf, mat, opts...)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := io.Copy(w, bytes.NewReader(payload)); err != nil {
		b.Fatal(err)
	}
	if err := w.Close(); err != nil {
		b.Fatal(err)
	}
	return cipherBuf.Bytes()
}

func writeBenchCipherFile(b *testing.B, ciphertext []byte) *os.File {
	b.Helper()
	file, err := os.CreateTemp("", "kryptograf-bench-cipher-*")
	if err != nil {
		b.Fatal(err)
	}
	if _, err := file.Write(ciphertext); err != nil {
		file.Close()
		os.Remove(file.Name())
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	})
	return file
}

func writeBenchCipherFileFromStream(b *testing.B, mat keymgmt.Material, payloadSize int64, opts ...Option) (*os.File, int64) {
	b.Helper()

	file, err := os.CreateTemp("", "kryptograf-bench-cipher-stream-*")
	if err != nil {
		b.Fatal(err)
	}

	writer, err := NewEncryptWriter(file, mat, opts...)
	if err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		b.Fatal(err)
	}

	pattern := bytes.Repeat([]byte("kryptograf-bench-large-pattern-"), 1024)
	if _, err := io.CopyN(writer, &benchPatternReader{pattern: pattern}, payloadSize); err != nil {
		_ = writer.Close()
		_ = file.Close()
		_ = os.Remove(file.Name())
		b.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		b.Fatal(err)
	}

	name := file.Name()
	info, err := os.Stat(name)
	if err != nil {
		_ = os.Remove(name)
		b.Fatal(err)
	}

	reopened, err := os.Open(name)
	if err != nil {
		_ = os.Remove(name)
		b.Fatal(err)
	}

	b.Cleanup(func() {
		_ = reopened.Close()
		_ = os.Remove(name)
	})

	return reopened, info.Size()
}

type benchCappedReader struct {
	r   io.Reader
	max int
}

func (r *benchCappedReader) Read(p []byte) (int, error) {
	if len(p) > r.max {
		p = p[:r.max]
	}
	return r.r.Read(p)
}

type benchPatternReader struct {
	pattern []byte
	offset  int
}

func (r *benchPatternReader) Read(p []byte) (int, error) {
	if len(r.pattern) == 0 {
		return 0, io.EOF
	}
	written := 0
	for written < len(p) {
		n := copy(p[written:], r.pattern[r.offset:])
		written += n
		r.offset += n
		if r.offset == len(r.pattern) {
			r.offset = 0
		}
	}
	return written, nil
}
