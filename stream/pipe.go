package stream

import (
	"io"

	"pkt.systems/kryptograf/keymgmt"
)

// NewEncryptPipe returns a reader that yields ciphertext and a write-closer
// that accepts plaintext. Closing the writer flushes all data and finalises the
// stream.
func NewEncryptPipe(material keymgmt.Material, opts ...Option) (*io.PipeReader, io.WriteCloser, error) {
	pr, pw := io.Pipe()

	writer, err := NewEncryptWriter(pw, material, opts...)
	if err != nil {
		pr.CloseWithError(err)
		pw.CloseWithError(err)
		return nil, nil, err
	}

	return pr, &pipeEncryptWriter{writer: writer, pipe: pw}, nil
}

// NewDecryptPipe returns a read-closer emitting plaintext and a pipe writer
// expecting ciphertext.
func NewDecryptPipe(material keymgmt.Material, opts ...Option) (io.ReadCloser, *io.PipeWriter, error) {
	pr, pw := io.Pipe()

	reader, err := NewDecryptReader(pr, material, opts...)
	if err != nil {
		pr.CloseWithError(err)
		pw.CloseWithError(err)
		return nil, nil, err
	}

	return reader, pw, nil
}

type pipeEncryptWriter struct {
	writer io.WriteCloser
	pipe   *io.PipeWriter
}

func (p *pipeEncryptWriter) Write(b []byte) (int, error) {
	return p.writer.Write(b)
}

func (p *pipeEncryptWriter) Close() error {
	err := p.writer.Close()
	if err != nil {
		p.pipe.CloseWithError(err)
		return err
	}
	return p.pipe.Close()
}
