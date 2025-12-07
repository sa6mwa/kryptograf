package stream

import (
	"bytes"
	"io"
	"sync"
	"testing"

	"pkt.systems/kryptograf/keymgmt"
)

// FuzzEncryptDecryptWithPool fuzzes payload and chunk sizes while using a shared buffer pool.
// It is light by default; run with `go test -run=Fuzz -fuzz=FuzzEncryptDecryptWithPool` for deeper coverage.
func FuzzEncryptDecryptWithPool(f *testing.F) {
	samples := []struct {
		chunk int
		len   int
	}{
		{2048, 1},
		{4096, 1024},
		{8192, 2048},
	}
	for _, s := range samples {
		payload := bytes.Repeat([]byte{0xAB}, s.len)
		f.Add(s.chunk, payload)
	}

	f.Fuzz(func(t *testing.T, chunk int, payload []byte) {
		if len(payload) == 0 {
			payload = []byte{0}
		}
		if chunk < minChunkSize {
			chunk = minChunkSize + (chunk % 4096)
		}
		if chunk > 32*1024 {
			chunk = 32 * 1024
		}

		var pool sync.Pool
		root, _ := keymgmt.GenerateRootKey()
		mat, _ := keymgmt.MintDEK(root, []byte("fuzz"))

		var cipherBuf bytes.Buffer
		w, err := NewEncryptWriter(&cipherBuf, mat, WithChunkSize(chunk), WithBufferPool(&pool))
		if err != nil {
			t.Fatalf("encrypt writer: %v", err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		r, err := NewDecryptReader(bytes.NewReader(cipherBuf.Bytes()), mat, WithChunkSize(chunk), WithBufferPool(&pool))
		if err != nil {
			t.Fatalf("decrypt reader: %v", err)
		}
		plain, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(plain, payload) {
			t.Fatalf("mismatch len=%d chunk=%d", len(payload), chunk)
		}
	})
}
