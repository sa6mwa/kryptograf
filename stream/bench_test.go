package stream

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"pkt.systems/kryptograf/cipher"
	"pkt.systems/kryptograf/keymgmt"
)

var benchPayload = bytes.Repeat([]byte("kryptograf-streaming-benchmark-"), 1<<12) // ~1 MiB

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
