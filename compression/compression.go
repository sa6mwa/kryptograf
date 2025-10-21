package compression

import "io"

// Adapter wraps streams with compression/decompression stages.
type Adapter interface {
	WrapWriter(io.Writer) (io.WriteCloser, error)
	WrapReader(io.Reader) (io.ReadCloser, error)
}
