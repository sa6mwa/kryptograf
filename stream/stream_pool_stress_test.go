package stream

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
	"os"

	"pkt.systems/kryptograf/keymgmt"
)

const (
	minChunk = minChunkSize
	maxChunk = 32 * 1024
)

// Stress the shared buffer pool under high parallelism to catch rare
// corruption/MAC issues. This mirrors lockd's workload where many goroutines
// reuse a single pool.
func TestBufferPoolStressConcurrent(t *testing.T) {
	const goroutines = 64
	const iterations = 200

	var pool sync.Pool
	root, _ := keymgmt.GenerateRootKey()

	errCh := make(chan error, goroutines)
	wg := sync.WaitGroup{}
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		seed := time.Now().UnixNano() + int64(g)
		r := rand.New(rand.NewSource(seed))

		go func(seed int64, r *rand.Rand) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				chunk := minChunk + r.Intn(maxChunk-minChunk)
				payloadLen := r.Intn(chunk*3) + 1 // up to ~3 chunks

				payload := make([]byte, payloadLen)
				if _, err := r.Read(payload); err != nil {
					errCh <- fmt.Errorf("rand read: %w", err)
					return
				}

				mat, err := keymgmt.MintDEK(root, []byte(fmt.Sprintf("stress-%d-%d", seed, i)))
				if err != nil {
					errCh <- err
					return
				}

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
					errCh <- err
					return
				}

				// Interleave GC/yield to churn the pool.
				if i%50 == 0 {
					runtime.GC()
				} else {
					runtime.Gosched()
				}

				rdr, err := NewDecryptReader(bytes.NewReader(cipherBuf.Bytes()), mat, WithChunkSize(chunk), WithBufferPool(&pool))
				if err != nil {
					errCh <- err
					return
				}
				plain, err := io.ReadAll(rdr)
				rdr.Close()
				if err != nil {
					errCh <- err
					return
				}
				if !bytes.Equal(plain, payload) {
					errCh <- fmt.Errorf("payload mismatch seed=%d iter=%d chunk=%d len=%d", seed, i, chunk, payloadLen)
					return
				}
			}
		}(seed, r)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("stress failure: %v", err)
		}
	}
}

// Simulate the lockd queue path: ciphertext streaming over an io.Pipe while many
// goroutines share a single buffer pool. This previously surfaced MAC failures
// when pooling was enabled.
func TestBufferPoolPipeConcurrent(t *testing.T) {
	goroutines := envOrDefault("KRYPTO_POOL_STRESS_G", 48)
	iterations := envOrDefault("KRYPTO_POOL_STRESS_ITERS", 80)
	const (
		chunkSize  = 8 * 1024
		maxPayload = 4 * 1024
	)

	var pool sync.Pool
	root, _ := keymgmt.GenerateRootKey()

	errCh := make(chan error, goroutines)
	wg := sync.WaitGroup{}
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		seed := time.Now().UnixNano() + int64(g*17)
		rnd := rand.New(rand.NewSource(seed))

		go func(seed int64, r *rand.Rand) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				payloadLen := r.Intn(maxPayload) + 1
				payload := make([]byte, payloadLen)
				if _, err := r.Read(payload); err != nil {
					errCh <- fmt.Errorf("rand read: %w", err)
					return
				}

				mat, err := keymgmt.MintDEK(root, []byte(fmt.Sprintf("pipe-%d-%d", seed, i)))
				if err != nil {
					errCh <- err
					return
				}

				pr, pw := io.Pipe()

				// Writer goroutine encrypts into the pipe using the shared pool.
				writerErr := make(chan error, 1)
				go func() {
					w, err := NewEncryptWriter(pw, mat, WithChunkSize(chunkSize), WithBufferPool(&pool))
					if err != nil {
						writerErr <- err
						return
					}
					if _, err := w.Write(payload); err != nil {
						writerErr <- err
						return
					}
					if err := w.Close(); err != nil {
						writerErr <- err
						return
					}
					_ = pw.Close()
					writerErr <- nil
				}()

				rdr, err := NewDecryptReader(pr, mat, WithChunkSize(chunkSize), WithBufferPool(&pool))
				if err != nil {
					errCh <- err
					return
				}
				plain, err := io.ReadAll(rdr)
				rdr.Close()
				if err != nil {
					errCh <- fmt.Errorf("read: %w", err)
					return
				}
				if err := <-writerErr; err != nil {
					errCh <- fmt.Errorf("writer: %w", err)
					return
				}
				if !bytes.Equal(plain, payload) {
					errCh <- fmt.Errorf("payload mismatch seed=%d iter=%d len=%d", seed, i, payloadLen)
					return
				}
			}
		}(seed, rnd)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("pipe stress failure: %v", err)
		}
	}
}

// Mirrors lockd's queue pipeline: encrypt to an io.Pipe, an independent
// goroutine copies ciphertext into a buffer (simulating the storage backend),
// then we decrypt from that buffer. This catches cases where pooled buffers
// are zeroed or reused while a different goroutine is still consuming the
// ciphertext.
func TestBufferPoolPipeStoreRoundTrip(t *testing.T) {
	goroutines := envOrDefault("KRYPTO_POOL_STRESS_G", 48)
	iterations := envOrDefault("KRYPTO_POOL_STRESS_ITERS", 80)
	const (
		chunkSize  = 8 * 1024
		maxPayload = 4 * 1024
	)

	var pool sync.Pool
	root, _ := keymgmt.GenerateRootKey()

	errCh := make(chan error, goroutines)
	wg := sync.WaitGroup{}
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		seed := time.Now().UnixNano() + int64(g*73)
		rnd := rand.New(rand.NewSource(seed))

		go func(seed int64, r *rand.Rand) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				plen := r.Intn(maxPayload) + 1
				payload := make([]byte, plen)
				if _, err := r.Read(payload); err != nil {
					errCh <- fmt.Errorf("rand read: %w", err)
					return
				}

				mat, err := keymgmt.MintDEK(root, []byte(fmt.Sprintf("pipe-store-%d-%d", seed, i)))
				if err != nil {
					errCh <- err
					return
				}

				pr, pw := io.Pipe()
				storeBuf := &bytes.Buffer{}

				writerDone := make(chan error, 1)
				go func() {
					w, err := NewEncryptWriter(pw, mat, WithChunkSize(chunkSize), WithBufferPool(&pool))
					if err != nil {
						writerDone <- err
						return
					}
					if _, err := w.Write(payload); err != nil {
						writerDone <- err
						return
					}
					if err := w.Close(); err != nil {
						writerDone <- err
						return
					}
					_ = pw.Close()
					writerDone <- nil
				}()

				storeDone := make(chan error, 1)
				go func() {
					_, err := io.Copy(storeBuf, pr)
					if err != nil {
						storeDone <- err
						return
					}
					storeDone <- nil
				}()

				if err := <-writerDone; err != nil {
					errCh <- fmt.Errorf("writer: %w", err)
					return
				}
				if err := <-storeDone; err != nil {
					errCh <- fmt.Errorf("store copy: %w", err)
					return
				}

				rdr, err := NewDecryptReader(bytes.NewReader(storeBuf.Bytes()), mat, WithChunkSize(chunkSize), WithBufferPool(&pool))
				if err != nil {
					errCh <- err
					return
				}
				plain, err := io.ReadAll(rdr)
				rdr.Close()
				if err != nil {
					errCh <- fmt.Errorf("decrypt: %w", err)
					return
				}
				if !bytes.Equal(plain, payload) {
					errCh <- fmt.Errorf("payload mismatch seed=%d iter=%d len=%d", seed, i, plen)
					return
				}
			}
		}(seed, rnd)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("pipe store stress failure: %v", err)
		}
	}
}

func envOrDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
