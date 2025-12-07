package stream

import (
	"sync"
	"sync/atomic"
)

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

func borrowBuffers(cfg config, overhead int) (*bufferSet, bool) {
	if cfg.bufferPool == nil {
		return newBufferSet(cfg.chunkSize, overhead), false
	}
	if v := cfg.bufferPool.Get(); v != nil {
		if bs, ok := v.(*bufferSet); ok && cap(bs.plain) >= cfg.chunkSize && cap(bs.cipher) >= cfg.chunkSize+overhead {
			bs.plain = bs.plain[:0]
			bs.cipher = bs.cipher[:0]
			// mark in-use for debug
			atomic.StoreUint32(&bs.inUse, 1)
			return bs, true
		}
	}
	bs := newBufferSet(cfg.chunkSize, overhead)
	atomic.StoreUint32(&bs.inUse, 1)
	return bs, true
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
