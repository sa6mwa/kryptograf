package stream

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"testing"
	"testing/quick"

	"pkt.systems/kryptograf/keymgmt"
)

// These allocation-focused tests guard the pooling optimisation so regressions
// surface quickly. Thresholds are intentionally loose to avoid brittleness
// across Go versions, but pooled paths must clearly allocate less than the
// unpooled paths and stay within a small fixed budget.

func TestEncryptWriterAllocsWithPool(t *testing.T) {
	const (
		chunk = 1024
		runs  = 50
	)
	root, _ := keymgmt.GenerateRootKey()
	mat, err := keymgmt.MintDEK(root, []byte("alloc-encrypt"))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	payload := bytes.Repeat([]byte("a"), chunk/2)

	var pool sync.Pool
	pool.Put(newBufferSet(chunk, 16)) // prime pool; AES-GCM overhead is 16 bytes

	allocsWithPool := testing.AllocsPerRun(runs, func() {
		var dst bytes.Buffer
		w, err := NewEncryptWriter(&dst, mat, WithChunkSize(chunk), WithBufferPool(&pool))
		if err != nil {
			t.Fatalf("writer: %v", err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	})

	allocsNoPool := testing.AllocsPerRun(runs, func() {
		var dst bytes.Buffer
		w, err := NewEncryptWriter(&dst, mat, WithChunkSize(chunk))
		if err != nil {
			t.Fatalf("writer: %v", err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	})

	if allocsWithPool >= allocsNoPool {
		t.Fatalf("expected pooled encrypt path to allocate less; with_pool=%.1f without_pool=%.1f", allocsWithPool, allocsNoPool)
	}
	if allocsWithPool > 20 {
		t.Fatalf("pooled encrypt path allocated too much: %.1f allocs/run (budget 20)", allocsWithPool)
	}
}

func TestDecryptReaderAllocsWithPool(t *testing.T) {
	const (
		chunk = 1024
		runs  = 50
	)
	root, _ := keymgmt.GenerateRootKey()
	mat, err := keymgmt.MintDEK(root, []byte("alloc-decrypt"))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	payload := bytes.Repeat([]byte("b"), chunk/2)

	var cipherBuf bytes.Buffer
	enc, err := NewEncryptWriter(&cipherBuf, mat, WithChunkSize(chunk))
	if err != nil {
		t.Fatalf("enc writer: %v", err)
	}
	enc.Write(payload)
	enc.Close()

	var pool sync.Pool
	pool.Put(newBufferSet(chunk, 16))

	allocsWithPool := testing.AllocsPerRun(runs, func() {
		r, err := NewDecryptReader(bytes.NewReader(cipherBuf.Bytes()), mat, WithChunkSize(chunk), WithBufferPool(&pool))
		if err != nil {
			t.Fatalf("reader: %v", err)
		}
		if _, err := io.ReadAll(r); err != nil {
			t.Fatalf("read: %v", err)
		}
		if err := r.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	})

	allocsNoPool := testing.AllocsPerRun(runs, func() {
		r, err := NewDecryptReader(bytes.NewReader(cipherBuf.Bytes()), mat, WithChunkSize(chunk))
		if err != nil {
			t.Fatalf("reader: %v", err)
		}
		if _, err := io.ReadAll(r); err != nil {
			t.Fatalf("read: %v", err)
		}
		if err := r.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	})

	if allocsWithPool >= allocsNoPool {
		t.Fatalf("expected pooled decrypt path to allocate less; with_pool=%.1f without_pool=%.1f", allocsWithPool, allocsNoPool)
	}
	if allocsWithPool > 20 {
		t.Fatalf("pooled decrypt path allocated too much: %.1f allocs/run (budget 20)", allocsWithPool)
	}
}

// Pool entries with the wrong type must be ignored safely.
func TestBufferPoolIgnoresWrongType(t *testing.T) {
	var pool sync.Pool
	pool.Put(struct{ junk int }{42})

	root, _ := keymgmt.GenerateRootKey()
	mat, _ := keymgmt.MintDEK(root, []byte("pool-wrong-type"))

	var dst bytes.Buffer
	w, err := NewEncryptWriter(&dst, mat, WithChunkSize(1024), WithBufferPool(&pool))
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	if _, err := w.Write([]byte("ok")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// Pool entries that are undersized must be replaced rather than reused.
func TestBufferPoolSkipsTooSmall(t *testing.T) {
	var pool sync.Pool
	// Too small for 2KiB chunk + overhead.
	pool.Put(&bufferSet{
		plain:  make([]byte, 0, 512),
		cipher: make([]byte, 0, 512),
	})

	root, _ := keymgmt.GenerateRootKey()
	mat, _ := keymgmt.MintDEK(root, []byte("pool-small"))
	var dst bytes.Buffer
	w, err := NewEncryptWriter(&dst, mat, WithChunkSize(2048), WithBufferPool(&pool))
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	if _, err := w.Write(bytes.Repeat([]byte("x"), 1500)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// Basic concurrency smoke test to ensure pooling paths don't corrupt data.
func TestConcurrentEncryptDecryptWithPool(t *testing.T) {
	const (
		chunk    = 2048
		messages = 32
	)
	var pool sync.Pool
	root, _ := keymgmt.GenerateRootKey()

	wg := sync.WaitGroup{}
	errCh := make(chan error, messages)

	for i := 0; i < messages; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			mat, err := keymgmt.MintDEK(root, []byte("conc-"+string(rune(i))))
			if err != nil {
				errCh <- err
				return
			}
			payload := bytes.Repeat([]byte{byte(i)}, 1024)
			var cipherBuf bytes.Buffer
			w, err := NewEncryptWriter(&cipherBuf, mat, WithChunkSize(chunk), WithBufferPool(&pool))
			if err != nil {
				errCh <- err
				return
			}
			if _, err := w.Write(payload); err != nil {
				errCh <- err
				return
			}
			if err := w.Close(); err != nil {
				err := err
				errCh <- err
				return
			}
			r, err := NewDecryptReader(bytes.NewReader(cipherBuf.Bytes()), mat, WithChunkSize(chunk), WithBufferPool(&pool))
			if err != nil {
				errCh <- err
				return
			}
			plain, err := io.ReadAll(r)
			r.Close()
			if err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(plain, payload) {
				errCh <- fmt.Errorf("payload mismatch on %d", i)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent path error: %v", err)
		}
	}
}

// Quick property-style check: random chunk sizes, payload lengths, and pool junk entries must roundtrip.
func TestEncryptDecryptPoolQuick(t *testing.T) {
	cfg := &quick.Config{MaxCount: 50}
	if err := quick.Check(func(chunk uint16, payloadLen uint16, junkType bool) bool {
		// constrain sizes
		cs := int(chunk)%8192 + 1024
		plen := int(payloadLen) % (cs * 3) // up to 3 chunks
		if plen == 0 {
			plen = 1
		}

		var pool sync.Pool
		if junkType {
			pool.Put(struct{ x int }{1})
		} else {
			pool.Put(&bufferSet{
				plain:  make([]byte, 0, cs/2),    // intentionally undersized sometimes
				cipher: make([]byte, 0, cs/2+16), // gcm overhead
			})
		}

		root, _ := keymgmt.GenerateRootKey()
		mat, err := keymgmt.MintDEK(root, []byte("quick"))
		if err != nil {
			t.Fatalf("mint: %v", err)
		}

		payload := bytes.Repeat([]byte{0xaa}, plen)
		var cipherBuf bytes.Buffer
		w, err := NewEncryptWriter(&cipherBuf, mat, WithChunkSize(cs), WithBufferPool(&pool))
		if err != nil {
			t.Fatalf("writer: %v", err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		r, err := NewDecryptReader(bytes.NewReader(cipherBuf.Bytes()), mat, WithChunkSize(cs), WithBufferPool(&pool))
		if err != nil {
			t.Fatalf("reader: %v", err)
		}
		plain, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return bytes.Equal(plain, payload)
	}, cfg); err != nil {
		t.Fatalf("quick check failed: %v", err)
	}
}
