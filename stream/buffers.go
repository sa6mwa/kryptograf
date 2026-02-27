package stream

import (
	"sync"
	"sync/atomic"
)

var builtInChunkBufferPoolDefault sync.Pool

// bufferSet groups plaintext and ciphertext scratch space used by stream
// readers/writers so they can be pooled together.
type bufferSet struct {
	plain  []byte
	cipher []byte
	inUse  uint32
}

func newBufferSet(chunkSize, overhead int) *bufferSet {
	return &bufferSet{
		plain:  make([]byte, 0, chunkSize),
		cipher: make([]byte, 0, chunkSize+overhead),
	}
}

func borrowBuffers(cfg config, overhead int) (*bufferSet, *sync.Pool) {
	pool := cfg.bufferPool
	if pool == nil {
		pool = builtInChunkBufferPool(cfg.chunkSize, overhead)
	}
	if pool == nil {
		return newBufferSet(cfg.chunkSize, overhead), nil
	}
	if v := pool.Get(); v != nil {
		if bs, ok := v.(*bufferSet); ok && cap(bs.plain) >= cfg.chunkSize && cap(bs.cipher) >= cfg.chunkSize+overhead {
			bs.plain = bs.plain[:0]
			bs.cipher = bs.cipher[:0]
			atomic.StoreUint32(&bs.inUse, 1)
			return bs, pool
		}
	}
	bs := newBufferSet(cfg.chunkSize, overhead)
	atomic.StoreUint32(&bs.inUse, 1)
	return bs, pool
}

func builtInChunkBufferPool(chunkSize, overhead int) *sync.Pool {
	// Keep internal pooling bounded to the default chunk profile. Callers that
	// tune chunk size can opt into explicit pooling with WithBufferPool.
	if chunkSize != defaultChunkSize {
		return nil
	}
	if overhead < 0 || overhead > 128 {
		return nil
	}
	return &builtInChunkBufferPoolDefault
}

func releaseBuffers(pool *sync.Pool, bs *bufferSet) {
	if pool == nil || bs == nil {
		return
	}
	if atomic.SwapUint32(&bs.inUse, 0) == 0 {
		// double release; signal via panic to catch corruption during tests
		panic("kryptograf/stream: bufferSet released twice or use-after-free detected")
	}
	zeroAll(bs.plain, cap(bs.plain))
	zeroAll(bs.cipher, cap(bs.cipher))
	bs.plain = bs.plain[:0]
	bs.cipher = bs.cipher[:0]
	pool.Put(bs)
}

func zeroAll(buf []byte, wantCap int) {
	if cap(buf) < wantCap {
		wantCap = cap(buf)
	}
	if wantCap == 0 {
		return
	}
	tmp := buf[:wantCap]
	for i := range tmp {
		tmp[i] = 0
	}
}
