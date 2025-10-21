package compression

import (
	"bytes"
	"io"
	"sync"

	"github.com/golang/snappy"
)

// Snappy returns a pooled adapter wrapping streams with Snappy compression.
func Snappy() Adapter {
	adapter := &snappyAdapter{}
	adapter.writerPool.New = func() any {
		return snappy.NewBufferedWriter(io.Discard)
	}
	adapter.readerPool.New = func() any {
		return snappy.NewReader(bytes.NewReader(nil))
	}
	return adapter
}

type snappyAdapter struct {
	writerPool sync.Pool
	readerPool sync.Pool
}

func (a *snappyAdapter) WrapWriter(w io.Writer) (io.WriteCloser, error) {
	sw := a.writerPool.Get().(*snappy.Writer)
	sw.Reset(w)
	return &snappyWriteCloser{Writer: sw, pool: &a.writerPool}, nil
}

func (a *snappyAdapter) WrapReader(r io.Reader) (io.ReadCloser, error) {
	sr := a.readerPool.Get().(*snappy.Reader)
	sr.Reset(r)
	return &snappyReadCloser{reader: sr, pool: &a.readerPool}, nil
}

type snappyWriteCloser struct {
	*snappy.Writer
	pool *sync.Pool
}

func (w *snappyWriteCloser) Close() error {
	err := w.Writer.Close()
	w.Writer.Reset(io.Discard)
	w.pool.Put(w.Writer)
	return err
}

type snappyReadCloser struct {
	reader *snappy.Reader
	pool   *sync.Pool
}

func (r *snappyReadCloser) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *snappyReadCloser) Close() error {
	r.reader.Reset(bytes.NewReader(nil))
	r.pool.Put(r.reader)
	return nil
}
