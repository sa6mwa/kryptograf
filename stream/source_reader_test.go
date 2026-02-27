package stream

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"runtime"
	"sync"
	"testing"

	"pkt.systems/kryptograf/keymgmt"
)

func TestDecryptReaderWithSourceReadBufferDisabled(t *testing.T) {
	root, _ := keymgmt.GenerateRootKey()
	mat, err := keymgmt.MintDEK(root, []byte("source-buffer-off"))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	plaintext := bytes.Repeat([]byte("payload"), 2048)
	ciphertext := encryptFixture(t, mat, plaintext)

	r, err := NewDecryptReader(bytes.NewReader(ciphertext), mat, WithSourceReadBuffer(0))
	if err != nil {
		t.Fatalf("new decrypt reader: %v", err)
	}
	defer r.Close()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestSourceReadBufferPoolIgnoresWrongType(t *testing.T) {
	var sourcePool sync.Pool
	sourcePool.Put(struct{ junk int }{junk: 7})

	root, _ := keymgmt.GenerateRootKey()
	mat, err := keymgmt.MintDEK(root, []byte("source-pool-wrong-type"))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	plaintext := bytes.Repeat([]byte("x"), 4096)
	ciphertext := encryptFixture(t, mat, plaintext)

	r, err := NewDecryptReader(
		bytes.NewReader(ciphertext),
		mat,
		WithSourceReadBuffer(4*1024),
		WithSourceReadBufferPool(&sourcePool),
	)
	if err != nil {
		t.Fatalf("new decrypt reader: %v", err)
	}
	defer r.Close()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestSourceReadBufferPoolIgnoresUndersizedReader(t *testing.T) {
	var sourcePool sync.Pool
	sourcePool.Put(bufio.NewReaderSize(bytes.NewReader(nil), 256))

	root, _ := keymgmt.GenerateRootKey()
	mat, err := keymgmt.MintDEK(root, []byte("source-pool-small"))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	plaintext := bytes.Repeat([]byte("y"), 4096)
	ciphertext := encryptFixture(t, mat, plaintext)

	r, err := NewDecryptReader(
		bytes.NewReader(ciphertext),
		mat,
		WithSourceReadBuffer(4*1024),
		WithSourceReadBufferPool(&sourcePool),
	)
	if err != nil {
		t.Fatalf("new decrypt reader: %v", err)
	}
	defer r.Close()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestDecryptReaderReturnsSourceReaderToPool(t *testing.T) {
	var sourcePool sync.Pool
	sourcePool.Put(bufio.NewReaderSize(bytes.NewReader(nil), 4*1024))

	root, _ := keymgmt.GenerateRootKey()
	mat, err := keymgmt.MintDEK(root, []byte("source-pool-return"))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	plaintext := bytes.Repeat([]byte("z"), 4096)
	ciphertext := encryptFixture(t, mat, plaintext)

	r, err := NewDecryptReader(
		bytes.NewReader(ciphertext),
		mat,
		WithSourceReadBuffer(4*1024),
		WithSourceReadBufferPool(&sourcePool),
	)
	if err != nil {
		t.Fatalf("new decrypt reader: %v", err)
	}
	if _, err := io.ReadAll(r); err != nil {
		t.Fatalf("read all: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got := sourcePool.Get()
	if got == nil {
		t.Skip("pool entry reclaimed by GC; cannot assert reuse")
	}
	reader, ok := got.(*bufio.Reader)
	if !ok {
		t.Fatalf("expected *bufio.Reader from source pool, got %T", got)
	}
	if reader.Size() < 4*1024 {
		t.Fatalf("expected pooled reader size >= 4096, got %d", reader.Size())
	}
}

func TestDecryptReaderSourceBufferStaysBoundedOnLargePayload(t *testing.T) {
	const (
		payloadSize         = 100 * 1024 * 1024
		sourceBufferSize    = 64 * 1024
		maxAllowedReadBytes = 1 * 1024 * 1024
		maxSingleAllocBytes = 1 * 1024 * 1024
		maxHeapGrowthBytes  = 1 * 1024 * 1024
		repeatRuns          = 12
	)

	root, _ := keymgmt.GenerateRootKey()
	mat, err := keymgmt.MintDEK(root, []byte("source-buffer-bounded-large"))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	cipherFile, err := os.CreateTemp("", "kryptograf-source-buffer-bounded-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer func() {
		_ = os.Remove(cipherFile.Name())
	}()

	w, err := NewEncryptWriter(cipherFile, mat)
	if err != nil {
		t.Fatalf("new encrypt writer: %v", err)
	}
	if _, err := io.CopyN(w, repeatedByteReader{b: 'x'}, payloadSize); err != nil {
		t.Fatalf("encrypt copy: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("encrypt close: %v", err)
	}

	cipherIn, err := os.Open(cipherFile.Name())
	if err != nil {
		t.Fatalf("open cipher file: %v", err)
	}
	defer cipherIn.Close()

	info, err := cipherIn.Stat()
	if err != nil {
		t.Fatalf("stat cipher file: %v", err)
	}

	src := &maxReadRequestRecorder{
		r: io.NewSectionReader(cipherIn, 0, info.Size()),
	}

	r, err := NewDecryptReader(src, mat, WithSourceReadBuffer(sourceBufferSize))
	if err != nil {
		t.Fatalf("new decrypt reader: %v", err)
	}
	n, err := io.Copy(io.Discard, r)
	if err != nil {
		t.Fatalf("decrypt copy: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("decrypt close: %v", err)
	}
	if n != payloadSize {
		t.Fatalf("unexpected plaintext size: got %d want %d", n, payloadSize)
	}
	if src.maxRequest > maxAllowedReadBytes {
		t.Fatalf("source read request too large: got %d bytes, want <= %d", src.maxRequest, maxAllowedReadBytes)
	}

	// Prove one 100MiB decrypt does not allocate anywhere near payload size.
	runtime.GC()
	runtime.GC()
	var singleBefore runtime.MemStats
	runtime.ReadMemStats(&singleBefore)
	if _, err := decryptLargeFixtureFile(cipherFile.Name(), info.Size(), mat, sourceBufferSize); err != nil {
		t.Fatalf("single decrypt pass: %v", err)
	}
	var singleAfter runtime.MemStats
	runtime.ReadMemStats(&singleAfter)
	singleAlloc := singleAfter.TotalAlloc - singleBefore.TotalAlloc
	if singleAlloc > maxSingleAllocBytes {
		t.Fatalf("single decrypt allocated too much: got %d bytes, want <= %d", singleAlloc, maxSingleAllocBytes)
	}

	// Prove repeated runs do not accumulate heap usage.
	runtime.GC()
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	baseHeap := base.HeapAlloc
	var maxObservedHeapGrowth uint64
	for i := 0; i < repeatRuns; i++ {
		if _, err := decryptLargeFixtureFile(cipherFile.Name(), info.Size(), mat, sourceBufferSize); err != nil {
			t.Fatalf("repeat decrypt %d: %v", i, err)
		}
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		var heapGrowth uint64
		if m.HeapAlloc > baseHeap {
			heapGrowth = m.HeapAlloc - baseHeap
		}
		if heapGrowth > maxObservedHeapGrowth {
			maxObservedHeapGrowth = heapGrowth
		}
		if heapGrowth > maxHeapGrowthBytes {
			t.Fatalf("heap grew cumulatively too much: got %d bytes, want <= %d", heapGrowth, maxHeapGrowthBytes)
		}
	}
	t.Logf("single_alloc=%dB max_heap_growth=%dB", singleAlloc, maxObservedHeapGrowth)
}

func encryptFixture(t *testing.T, mat keymgmt.Material, plaintext []byte, opts ...Option) []byte {
	t.Helper()
	var cipherBuf bytes.Buffer
	w, err := NewEncryptWriter(&cipherBuf, mat, opts...)
	if err != nil {
		t.Fatalf("encrypt writer: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("encrypt write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("encrypt close: %v", err)
	}
	return cipherBuf.Bytes()
}

type repeatedByteReader struct {
	b byte
}

func (r repeatedByteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

type maxReadRequestRecorder struct {
	r          io.Reader
	maxRequest int
}

func (r *maxReadRequestRecorder) Read(p []byte) (int, error) {
	if len(p) > r.maxRequest {
		r.maxRequest = len(p)
	}
	return r.r.Read(p)
}

func decryptLargeFixtureFile(path string, cipherSize int64, mat keymgmt.Material, sourceBufferSize int) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	src := io.NewSectionReader(f, 0, cipherSize)
	r, err := NewDecryptReader(src, mat, WithSourceReadBuffer(sourceBufferSize))
	if err != nil {
		return 0, err
	}
	defer r.Close()

	n, err := io.Copy(io.Discard, r)
	if err != nil {
		return 0, err
	}
	return n, nil
}
