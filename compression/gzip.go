package compression

import (
	"compress/gzip"
	"io"
	"sync"
)

// Gzip returns an adapter using gzip at the provided level. If level is 0, gzip.BestSpeed is used.
func Gzip(level int) Adapter {
	if level == 0 {
		level = gzip.BestSpeed
	}
	adapter := &gzipAdapter{level: level}
	adapter.writerPool.New = func() any {
		w, err := gzip.NewWriterLevel(io.Discard, level)
		if err != nil {
			panic(err)
		}
		return w
	}
	return adapter
}

var defaultGzip Adapter = Gzip(gzip.BestSpeed)

// GzipDefault exposes a gzip adapter using BestSpeed.
func GzipDefault() Adapter { return defaultGzip }

type gzipAdapter struct {
	level      int
	writerPool sync.Pool
}

func (a *gzipAdapter) WrapWriter(w io.Writer) (io.WriteCloser, error) {
	gw := a.writerPool.Get().(*gzip.Writer)
	gw.Reset(w)
	return &pooledGzipWriter{Writer: gw, pool: &a.writerPool}, nil
}

func (a *gzipAdapter) WrapReader(r io.Reader) (io.ReadCloser, error) {
	return gzip.NewReader(r)
}

type pooledGzipWriter struct {
	*gzip.Writer
	pool *sync.Pool
}

func (w *pooledGzipWriter) Close() error {
	err := w.Writer.Close()
	w.Writer.Reset(io.Discard)
	w.pool.Put(w.Writer)
	return err
}
