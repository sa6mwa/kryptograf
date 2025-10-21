package compression

import (
	"bytes"
	"io"
	"sync"

	"github.com/pierrec/lz4/v4"
)

// LZ4 returns a pooled adapter wrapping readers and writers with LZ4 compression.
func LZ4() Adapter {
	adapter := &lz4Adapter{}
	adapter.writerPool.New = func() any {
		w := lz4.NewWriter(io.Discard)
		return w
	}
	adapter.readerPool.New = func() any {
		r := lz4.NewReader(bytes.NewReader(nil))
		return r
	}
	return adapter
}

type lz4Adapter struct {
	writerPool sync.Pool
	readerPool sync.Pool
}

func (a *lz4Adapter) WrapWriter(w io.Writer) (io.WriteCloser, error) {
	lw := a.writerPool.Get().(*lz4.Writer)
	lw.Reset(w)
	return &lz4WriteCloser{Writer: lw, pool: &a.writerPool}, nil
}

func (a *lz4Adapter) WrapReader(r io.Reader) (io.ReadCloser, error) {
	lr := a.readerPool.Get().(*lz4.Reader)
	lr.Reset(r)
	return &lz4ReadCloser{reader: lr, pool: &a.readerPool}, nil
}

type lz4WriteCloser struct {
	*lz4.Writer
	pool *sync.Pool
}

func (w *lz4WriteCloser) Close() error {
	err := w.Writer.Close()
	w.Writer.Reset(io.Discard)
	w.pool.Put(w.Writer)
	return err
}

type lz4ReadCloser struct {
	reader *lz4.Reader
	pool   *sync.Pool
}

func (r *lz4ReadCloser) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *lz4ReadCloser) Close() error {
	r.reader.Reset(bytes.NewReader(nil))
	r.pool.Put(r.reader)
	return nil
}
