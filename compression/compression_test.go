package compression

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestAdaptersRoundTrip(t *testing.T) {
	adapters := []struct {
		name    string
		adapter Adapter
	}{
		{"gzip", GzipDefault()},
		{"snappy", Snappy()},
		{"lz4", LZ4()},
	}

	payload := bytes.Repeat([]byte("kryptograf"), 1024)

	for _, tc := range adapters {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			writer, err := tc.adapter.WrapWriter(&buf)
			if err != nil {
				t.Fatalf("WrapWriter: %v", err)
			}
			if _, err := writer.Write(payload); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			reader, err := tc.adapter.WrapReader(&buf)
			if err != nil {
				t.Fatalf("WrapReader: %v", err)
			}
			decompressed, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if err := reader.Close(); err != nil {
				t.Fatalf("Close reader: %v", err)
			}
			if !bytes.Equal(decompressed, payload) {
				t.Fatalf("roundtrip mismatch: got %d bytes", len(decompressed))
			}
		})
	}
}

func TestAdapterWriterError(t *testing.T) {
	adapter := Snappy()
	failing := &failWriter{}
	writer, err := adapter.WrapWriter(failing)
	if err != nil {
		t.Fatalf("WrapWriter: %v", err)
	}
	if _, err := writer.Write([]byte("hello")); err != nil && !errors.Is(err, errFail) {
		t.Fatalf("unexpected write error: %v", err)
	}
	if err := writer.Close(); !errors.Is(err, errFail) {
		t.Fatalf("expected errFail on close, got %v", err)
	}
}

func TestAdapterReaderError(t *testing.T) {
	adapter := LZ4()
	data := []byte("corrupted")
	reader, err := adapter.WrapReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("WrapReader: %v", err)
	}
	buf := make([]byte, 16)
	_, err = reader.Read(buf)
	if err == nil {
		t.Fatalf("expected read error")
	}
}

type failWriter struct{}

var errFail = errors.New("fail")

func (f *failWriter) Write([]byte) (int, error) {
	return 0, errFail
}
