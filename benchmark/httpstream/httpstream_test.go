package httpstream_test

import (
	bytes "bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/snappy"
	lz4 "github.com/pierrec/lz4/v4"
	"pkt.systems/kryptograf"
	"pkt.systems/kryptograf/cipher"
	"pkt.systems/kryptograf/keymgmt"
	stream "pkt.systems/kryptograf/stream"
)

var benchPayload = bytes.Repeat([]byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit."), 1<<12)

func BenchmarkHTTPStream(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reader := bytes.NewReader(benchPayload)
		io.Copy(w, reader)
	}))
	defer server.Close()

	client := server.Client()
	root, _ := keymgmt.GenerateRootKey()
	kg := kryptograf.New(root)

	baseline := func(b *testing.B) {
		b.SetBytes(int64(len(benchPayload)))
		b.ResetTimer()
		for b.Loop() {
			resp, err := client.Get(server.URL)
			if err != nil {
				b.Fatalf("GET: %v", err)
			}
			_, err = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if err != nil {
				b.Fatalf("copy: %v", err)
			}
		}
	}

	encBench := func(mat kryptograf.Material, opts []stream.Option) func(*testing.B) {
		return func(b *testing.B) {
			b.SetBytes(int64(len(benchPayload)))
			b.ResetTimer()
			for b.Loop() {
				resp, err := client.Get(server.URL)
				if err != nil {
					b.Fatalf("GET: %v", err)
				}
				writer, err := kg.EncryptWriter(io.Discard, mat, opts...)
				if err != nil {
					b.Fatalf("EncryptWriter: %v", err)
				}
				if _, err := io.Copy(writer, resp.Body); err != nil {
					b.Fatalf("copy: %v", err)
				}
				if err := writer.Close(); err != nil {
					b.Fatalf("close: %v", err)
				}
				resp.Body.Close()
			}
		}
	}

	b.Run("baseline", baseline)

	aesGCMMat, err := kg.MintDEK([]byte("bench-aesgcm"))
	if err != nil {
		b.Fatalf("MintDEK: %v", err)
	}
	chachaMat, err := kg.MintDEK([]byte("bench-chacha"))
	if err != nil {
		b.Fatalf("MintDEK: %v", err)
	}
	chachaPFMat, err := kg.MintDEK([]byte("bench-chacha-pf"))
	if err != nil {
		b.Fatalf("MintDEK: %v", err)
	}
	xchachaMat, err := kg.MintDEKWithNonceSize([]byte("bench-xchacha"), 24)
	if err != nil {
		b.Fatalf("MintDEKWithNonceSize: %v", err)
	}
	xchachaPFMat, err := kg.MintDEKWithNonceSize([]byte("bench-xchacha-pf"), 24)
	if err != nil {
		b.Fatalf("MintDEKWithNonceSize: %v", err)
	}
	aesSIVMat, err := kg.MintDEK([]byte("bench-aessiv"))
	if err != nil {
		b.Fatalf("MintDEK: %v", err)
	}

	ciphers := []struct {
		name string
		mat  kryptograf.Material
		opts []stream.Option
	}{
		{"aes-gcm", aesGCMMat, nil},
		{"chacha20", chachaMat, []stream.Option{stream.WithCipher(cipher.ChaCha20Poly1305())}},
		{"chacha20pf", chachaPFMat, []stream.Option{stream.WithCipher(cipher.ChaCha20Poly1305PerFrame())}},
		{"xchacha20", xchachaMat, []stream.Option{stream.WithCipher(cipher.XChaCha20Poly1305())}},
		{"xchacha20pf", xchachaPFMat, []stream.Option{stream.WithCipher(cipher.XChaCha20Poly1305PerFrame())}},
		{"aes-gcmsiv", aesSIVMat, []stream.Option{stream.WithCipher(cipher.AESGCMSIV())}},
	}

	for _, c := range ciphers {
		b.Run(c.name, encBench(c.mat, c.opts))
	}

	baselineGzip := func(b *testing.B) {
		b.SetBytes(int64(len(benchPayload)))
		b.ResetTimer()
		for b.Loop() {
			resp, err := client.Get(server.URL)
			if err != nil {
				b.Fatalf("GET: %v", err)
			}
			gw := gzip.NewWriter(io.Discard)
			if _, err := io.Copy(gw, resp.Body); err != nil {
				b.Fatalf("copy: %v", err)
			}
			if err := gw.Close(); err != nil {
				b.Fatalf("gzip close: %v", err)
			}
			resp.Body.Close()
		}
	}

	baselineSnappy := func(b *testing.B) {
		b.SetBytes(int64(len(benchPayload)))
		b.ResetTimer()
		for b.Loop() {
			resp, err := client.Get(server.URL)
			if err != nil {
				b.Fatalf("GET: %v", err)
			}
			sw := snappy.NewBufferedWriter(io.Discard)
			if _, err := io.Copy(sw, resp.Body); err != nil {
				resp.Body.Close()
				b.Fatalf("copy: %v", err)
			}
			if err := sw.Close(); err != nil {
				resp.Body.Close()
				b.Fatalf("snappy close: %v", err)
			}
			resp.Body.Close()
		}
	}
	baselineLZ4 := func(b *testing.B) {
		b.SetBytes(int64(len(benchPayload)))
		b.ResetTimer()
		for b.Loop() {
			resp, err := client.Get(server.URL)
			if err != nil {
				b.Fatalf("GET: %v", err)
			}
			lw := lz4.NewWriter(io.Discard)
			if _, err := io.Copy(lw, resp.Body); err != nil {
				resp.Body.Close()
				b.Fatalf("copy: %v", err)
			}
			if err := lw.Close(); err != nil {
				resp.Body.Close()
				b.Fatalf("lz4 close: %v", err)
			}
			resp.Body.Close()
		}
	}
	variants := []struct {
		suffix   string
		baseline func(*testing.B)
		option   stream.Option
	}{
		{suffix: "+gzip", baseline: baselineGzip, option: stream.WithGzip()},
		{suffix: "+snappy", baseline: baselineSnappy, option: stream.WithSnappy()},
		{suffix: "+lz4", baseline: baselineLZ4, option: stream.WithLZ4()},
	}

	for _, variant := range variants {
		b.Run("baseline"+variant.suffix, variant.baseline)
		for _, c := range ciphers {
			opts := append([]stream.Option{}, c.opts...)
			opts = append(opts, variant.option)
			b.Run(c.name+variant.suffix, encBench(c.mat, opts))
		}
	}
}
