package stream

import (
	"bufio"
	"io"
	"sync"
)

var (
	sourceReadBytePool8K      sync.Pool
	sourceReadBytePool16K     sync.Pool
	sourceReadBytePool32K     sync.Pool
	sourceReadBytePool64K     sync.Pool
	sourceReadBufferStatePool sync.Pool
)

const sourceReadBufferPrefetchCap = 4 * 1024

type sourceReadBytes struct {
	buf []byte
}

type sourceReaderLease struct {
	bufioReader *bufio.Reader
	bufioPool   *sync.Pool
	fastReader  *sourceReadBuffer
	byteState   *sourceReadBytes
	bytePool    *sync.Pool
}

func wrapSourceReader(src io.Reader, cfg config) (io.Reader, sourceReaderLease) {
	size := cfg.sourceReadBufferSize
	if size <= 0 {
		return src, sourceReaderLease{}
	}

	if pool := cfg.sourceReadBufferPool; pool != nil {
		reader := borrowSourceBufferedReader(src, size, pool)
		return reader, sourceReaderLease{
			bufioReader: reader,
			bufioPool:   pool,
		}
	}

	bytePool := builtInSourceReadBytePool(size)
	byteBuf, byteState := borrowSourceReadBytes(size, bytePool)
	fastReader := borrowSourceReadBuffer(src, byteBuf)
	return src, sourceReaderLease{
		fastReader: fastReader,
		byteState:  byteState,
		bytePool:   bytePool,
	}
}

func (l *sourceReaderLease) release() {
	if l.bufioReader != nil && l.bufioPool != nil {
		l.bufioReader.Reset(eofReader{})
		l.bufioPool.Put(l.bufioReader)
	}
	if l.fastReader != nil {
		l.fastReader.reset(nil, nil)
		sourceReadBufferStatePool.Put(l.fastReader)
	}
	if l.byteState != nil && l.bytePool != nil {
		l.byteState.buf = l.byteState.buf[:cap(l.byteState.buf)]
		l.bytePool.Put(l.byteState)
	}
	l.bufioReader = nil
	l.bufioPool = nil
	l.fastReader = nil
	l.byteState = nil
	l.bytePool = nil
}

func borrowSourceBufferedReader(src io.Reader, size int, pool *sync.Pool) *bufio.Reader {
	if pool != nil {
		if v := pool.Get(); v != nil {
			if r, ok := v.(*bufio.Reader); ok && r.Size() >= size {
				r.Reset(src)
				return r
			}
		}
	}
	return bufio.NewReaderSize(src, size)
}

func builtInSourceReadBytePool(size int) *sync.Pool {
	switch size {
	case 8 * 1024:
		return &sourceReadBytePool8K
	case 16 * 1024:
		return &sourceReadBytePool16K
	case 32 * 1024:
		return &sourceReadBytePool32K
	case 64 * 1024:
		return &sourceReadBytePool64K
	default:
		return nil
	}
}

func borrowSourceReadBytes(size int, pool *sync.Pool) ([]byte, *sourceReadBytes) {
	if pool != nil {
		if v := pool.Get(); v != nil {
			if state, ok := v.(*sourceReadBytes); ok && cap(state.buf) >= size {
				state.buf = state.buf[:size]
				return state.buf, state
			}
		}
		state := &sourceReadBytes{buf: make([]byte, size)}
		return state.buf, state
	}
	return make([]byte, size), nil
}

func borrowSourceReadBuffer(src io.Reader, buf []byte) *sourceReadBuffer {
	if v := sourceReadBufferStatePool.Get(); v != nil {
		if r, ok := v.(*sourceReadBuffer); ok {
			r.reset(src, buf)
			return r
		}
	}
	return &sourceReadBuffer{src: src, buf: buf}
}

// sourceReadBuffer is a minimal buffered reader tuned for decrypt framing.
// It only supports Read and keeps a bounded fixed-size backing buffer.
type sourceReadBuffer struct {
	src io.Reader
	buf []byte
	r   int
	w   int
}

func (s *sourceReadBuffer) reset(src io.Reader, buf []byte) {
	s.src = src
	s.buf = buf
	s.r = 0
	s.w = 0
}

func (s *sourceReadBuffer) readFull(dst []byte) error {
	if len(dst) == 0 {
		return nil
	}
	if len(s.buf) == 0 {
		_, err := io.ReadFull(s.src, dst)
		return err
	}

	n := 0
	for n < len(dst) {
		if s.r < s.w {
			copied := copy(dst[n:], s.buf[s.r:s.w])
			s.r += copied
			n += copied
			continue
		}

		s.r = 0
		s.w = 0

		remaining := len(dst) - n
		// Large reads bypass the staging buffer after draining leftovers.
		if remaining >= len(s.buf)/2 {
			_, err := io.ReadFull(s.src, dst[n:])
			return err
		}

		prefetch := sourceReadBufferPrefetchCap
		if prefetch > len(s.buf) {
			prefetch = len(s.buf)
		}
		if remaining > prefetch {
			prefetch = remaining
		}
		if prefetch > len(s.buf) {
			prefetch = len(s.buf)
		}

		readN, err := s.src.Read(s.buf[:prefetch])
		if readN > 0 {
			s.w = readN
			continue
		}

		if err == nil {
			return io.ErrNoProgress
		}
		return err
	}
	return nil
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) {
	return 0, io.EOF
}
