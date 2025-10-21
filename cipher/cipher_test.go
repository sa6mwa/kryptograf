package cipher

import (
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestAESGCMFactory(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	factory := AESGCM()
	aead, err := factory(key)
	if err != nil {
		t.Fatalf("AESGCM factory error: %v", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read nonce: %v", err)
	}

	plaintext := []byte("hello world")
	ciphertext, err := aead.Seal(nil, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("Seal error: %v", err)
	}

	decrypted, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted mismatch")
	}
}

func TestChaCha20Poly1305Factory(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	factory := ChaCha20Poly1305()
	aead, err := factory(key)
	if err != nil {
		t.Fatalf("ChaCha20 factory error: %v", err)
	}

	if aead.NonceSize() != 12 {
		t.Fatalf("expected nonce size 12, got %d", aead.NonceSize())
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read nonce: %v", err)
	}

	plaintext := []byte("chacha plaintext")
	aad := []byte("aad")
	ciphertext, err := aead.Seal(nil, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal error: %v", err)
	}
	decrypted, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted mismatch")
	}
}

func TestChaCha20Poly1305PerFrameFactory(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	factory := ChaCha20Poly1305PerFrame()
	aead, err := factory(key)
	if err != nil {
		t.Fatalf("per-frame factory error: %v", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read nonce: %v", err)
	}
	msg := []byte("per-frame chacha")
	ct, err := aead.Seal(nil, nonce, msg, nil)
	if err != nil {
		t.Fatalf("Seal error: %v", err)
	}
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if string(pt) != string(msg) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestXChaCha20Poly1305Factory(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	factory := XChaCha20Poly1305()
	aead, err := factory(key)
	if err != nil {
		t.Fatalf("XChaCha20 factory error: %v", err)
	}

	if aead.NonceSize() != chacha20poly1305.NonceSizeX {
		t.Fatalf("unexpected nonce size: %d", aead.NonceSize())
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read nonce: %v", err)
	}

	msg := []byte("xchacha")
	aad := []byte("aad")

	ct, err := aead.Seal(nil, nonce, msg, aad)
	if err != nil {
		t.Fatalf("Seal error: %v", err)
	}
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if string(pt) != string(msg) {
		t.Fatalf("incorrect plaintext")
	}
}

func TestXChaCha20Poly1305PerFrameFactory(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)
	factory := XChaCha20Poly1305PerFrame()
	aead, err := factory(key)
	if err != nil {
		t.Fatalf("per-frame xchacha factory error: %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	msg := []byte("per-frame xchacha")
	ct, err := aead.Seal(nil, nonce, msg, nil)
	if err != nil {
		t.Fatalf("Seal error: %v", err)
	}
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if string(pt) != string(msg) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestAESGCMSIVFactory(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	factory := AESGCMSIV()
	aead, err := factory(key)
	if err != nil {
		t.Fatalf("AESGCMSIV factory error: %v", err)
	}

	if aead.NonceSize() != 12 {
		t.Fatalf("expected nonce size 12, got %d", aead.NonceSize())
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read nonce: %v", err)
	}
	msg := []byte("siv message")
	aad := []byte("aad")

	ct, err := aead.Seal(nil, nonce, msg, aad)
	if err != nil {
		t.Fatalf("Seal error: %v", err)
	}
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if string(pt) != string(msg) {
		t.Fatalf("incorrect plaintext")
	}
}
