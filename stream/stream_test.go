package stream

import (
	"bytes"
	"io"
	"testing"

	"pkt.systems/kryptograf/cipher"
	"pkt.systems/kryptograf/keymgmt"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	root, _ := keymgmt.GenerateRootKey()
	mat, err := keymgmt.MintDEK(root, []byte("ctx"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}
	var buf bytes.Buffer
	writer, err := NewEncryptWriter(&buf, mat)
	if err != nil {
		t.Fatalf("NewEncryptWriter error: %v", err)
	}

	plaintext := bytes.Repeat([]byte("hello world "), 8192)
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatalf("writer.Write error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close error: %v", err)
	}

	reader, err := NewDecryptReader(bytes.NewReader(buf.Bytes()), mat)
	if err != nil {
		t.Fatalf("NewDecryptReader error: %v", err)
	}
	defer reader.Close()

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("io.ReadAll error: %v", err)
	}

	if !bytes.Equal(plaintext, out) {
		t.Fatalf("plaintext mismatch after roundtrip")
	}
}

func TestEncryptDecryptWithCompressionAdapters(t *testing.T) {
	root, _ := keymgmt.GenerateRootKey()
	adapters := []struct {
		name   string
		option Option
	}{
		{"gzip", WithGzip()},
		{"snappy", WithSnappy()},
		{"lz4", WithLZ4()},
	}

	plaintext := bytes.Repeat([]byte("abcd"), 32*1024)

	for _, tc := range adapters {
		mat, err := keymgmt.MintDEK(root, []byte("cmp-"+tc.name))
		if err != nil {
			t.Fatalf("MintDEK error: %v", err)
		}
		var buf bytes.Buffer
		writer, err := NewEncryptWriter(&buf, mat, tc.option)
		if err != nil {
			t.Fatalf("NewEncryptWriter error: %v", err)
		}
		if _, err := writer.Write(plaintext); err != nil {
			t.Fatalf("Write error: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("Close error: %v", err)
		}

		reader, err := NewDecryptReader(bytes.NewReader(buf.Bytes()), mat, tc.option)
		if err != nil {
			t.Fatalf("NewDecryptReader error: %v", err)
		}
		out, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatalf("ReadAll error: %v", err)
		}
		if !bytes.Equal(out, plaintext) {
			t.Fatalf("%s roundtrip mismatch", tc.name)
		}
	}
}

func TestNewEncryptPipe(t *testing.T) {
	root, _ := keymgmt.GenerateRootKey()
	mat, err := keymgmt.MintDEK(root, []byte("pipe"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}
	reader, writer, err := NewEncryptPipe(mat)
	if err != nil {
		t.Fatalf("NewEncryptPipe error: %v", err)
	}
	defer reader.Close()

	plaintext := []byte("pipe data")
	go func() {
		defer writer.Close()
		_, _ = writer.Write(plaintext)
	}()

	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatalf("expected ciphertext from pipe")
	}
}

func TestNewDecryptPipe(t *testing.T) {
	root, _ := keymgmt.GenerateRootKey()
	mat, err := keymgmt.MintDEK(root, []byte("pipe decrypt"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}
	var buf bytes.Buffer
	writer, _ := NewEncryptWriter(&buf, mat)
	writer.Write([]byte("hello"))
	writer.Close()

	plaintextReader, cipherWriter, err := NewDecryptPipe(mat)
	if err != nil {
		t.Fatalf("NewDecryptPipe error: %v", err)
	}
	defer plaintextReader.Close()

	go func() {
		defer cipherWriter.Close()
		_, _ = cipherWriter.Write(buf.Bytes())
	}()

	out, err := io.ReadAll(plaintextReader)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(out) != "hello" {
		t.Fatalf("unexpected plaintext: %s", string(out))
	}
}

func TestEncryptDecryptWithChaCha(t *testing.T) {
	root, _ := keymgmt.GenerateRootKey()
	mat, err := keymgmt.MintDEK(root, []byte("chacha"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}
	var buf bytes.Buffer
	writer, err := NewEncryptWriter(&buf, mat, WithCipher(cipher.ChaCha20Poly1305()))
	if err != nil {
		t.Fatalf("NewEncryptWriter error: %v", err)
	}
	if _, err := writer.Write([]byte("hello chacha")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	reader, err := NewDecryptReader(bytes.NewReader(buf.Bytes()), mat, WithCipher(cipher.ChaCha20Poly1305()))
	if err != nil {
		t.Fatalf("NewDecryptReader error: %v", err)
	}
	defer reader.Close()

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(out) != "hello chacha" {
		t.Fatalf("unexpected plaintext: %s", string(out))
	}
}

func TestEncryptDecryptWithChaChaPerFrame(t *testing.T) {
	root, _ := keymgmt.GenerateRootKey()
	mat, err := keymgmt.MintDEK(root, []byte("chacha-per-frame"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}
	var buf bytes.Buffer
	writer, err := NewEncryptWriter(&buf, mat, WithCipher(cipher.ChaCha20Poly1305PerFrame()))
	if err != nil {
		t.Fatalf("NewEncryptWriter error: %v", err)
	}
	if _, err := writer.Write([]byte("hello chacha per frame")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	reader, err := NewDecryptReader(bytes.NewReader(buf.Bytes()), mat, WithCipher(cipher.ChaCha20Poly1305PerFrame()))
	if err != nil {
		t.Fatalf("NewDecryptReader error: %v", err)
	}
	defer reader.Close()

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(out) != "hello chacha per frame" {
		t.Fatalf("unexpected plaintext: %s", string(out))
	}
}

func TestEncryptDecryptWithXChaCha(t *testing.T) {
	root, _ := keymgmt.GenerateRootKey()
	mat, err := keymgmt.MintDEKWithNonceSize(root, []byte("xchacha"), 24)
	if err != nil {
		t.Fatalf("MintDEKWithNonceSize error: %v", err)
	}
	var buf bytes.Buffer
	writer, err := NewEncryptWriter(&buf, mat, WithCipher(cipher.XChaCha20Poly1305()))
	if err != nil {
		t.Fatalf("NewEncryptWriter error: %v", err)
	}
	if _, err := writer.Write([]byte("hello xchacha")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	reader, err := NewDecryptReader(bytes.NewReader(buf.Bytes()), mat, WithCipher(cipher.XChaCha20Poly1305()))
	if err != nil {
		t.Fatalf("NewDecryptReader error: %v", err)
	}
	defer reader.Close()

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(out) != "hello xchacha" {
		t.Fatalf("unexpected plaintext: %s", string(out))
	}
}

func TestEncryptDecryptWithXChaChaPerFrame(t *testing.T) {
	root, _ := keymgmt.GenerateRootKey()
	mat, err := keymgmt.MintDEKWithNonceSize(root, []byte("xchacha-per-frame"), 24)
	if err != nil {
		t.Fatalf("MintDEKWithNonceSize error: %v", err)
	}
	var buf bytes.Buffer
	writer, err := NewEncryptWriter(&buf, mat, WithCipher(cipher.XChaCha20Poly1305PerFrame()))
	if err != nil {
		t.Fatalf("NewEncryptWriter error: %v", err)
	}
	if _, err := writer.Write([]byte("hello xchacha per frame")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	reader, err := NewDecryptReader(bytes.NewReader(buf.Bytes()), mat, WithCipher(cipher.XChaCha20Poly1305PerFrame()))
	if err != nil {
		t.Fatalf("NewDecryptReader error: %v", err)
	}
	defer reader.Close()

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(out) != "hello xchacha per frame" {
		t.Fatalf("unexpected plaintext: %s", string(out))
	}
}

func TestEncryptDecryptWithAESGCMSIV(t *testing.T) {
	root, _ := keymgmt.GenerateRootKey()
	mat, err := keymgmt.MintDEK(root, []byte("siv"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}
	var buf bytes.Buffer
	writer, err := NewEncryptWriter(&buf, mat, WithCipher(cipher.AESGCMSIV()))
	if err != nil {
		t.Fatalf("NewEncryptWriter error: %v", err)
	}
	if _, err := writer.Write([]byte("hello siv")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	reader, err := NewDecryptReader(bytes.NewReader(buf.Bytes()), mat, WithCipher(cipher.AESGCMSIV()))
	if err != nil {
		t.Fatalf("NewDecryptReader error: %v", err)
	}
	defer reader.Close()

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(out) != "hello siv" {
		t.Fatalf("unexpected plaintext: %s", string(out))
	}
}
