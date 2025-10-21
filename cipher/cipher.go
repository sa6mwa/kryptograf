package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"
	"slices"

	siv "github.com/secure-io/siv-go"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Cipher encapsulates the primitives required to seal and open frame payloads.
type Cipher interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, aad []byte) ([]byte, error)
	Open(dst, nonce, ciphertext, aad []byte) ([]byte, error)
}

// Factory constructs a Cipher instance from the provided key material.
type Factory func(key []byte) (Cipher, error)

type aeadCipher struct {
	aead cipher.AEAD
}

func (c *aeadCipher) NonceSize() int { return c.aead.NonceSize() }

func (c *aeadCipher) Overhead() int { return c.aead.Overhead() }

func (c *aeadCipher) Seal(dst, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(nonce) != c.aead.NonceSize() {
		return nil, fmt.Errorf("cipher: invalid nonce length")
	}
	return c.aead.Seal(dst, nonce, plaintext, aad), nil
}

func (c *aeadCipher) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != c.aead.NonceSize() {
		return nil, fmt.Errorf("cipher: invalid nonce length")
	}
	return c.aead.Open(dst, nonce, ciphertext, aad)
}

// AESGCM returns a factory that produces AES-GCM ciphers.
func AESGCM() Factory {
	return func(key []byte) (Cipher, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		return &aeadCipher{aead: aead}, nil
	}
}

// ChaCha20Poly1305 returns a factory that produces ChaCha20-Poly1305 ciphers.
func ChaCha20Poly1305() Factory {
	return func(key []byte) (Cipher, error) {
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		return &aeadCipher{aead: aead}, nil
	}
}

// ChaCha20Poly1305PerFrame derives a fresh key for every frame via HKDF.
func ChaCha20Poly1305PerFrame() Factory {
	return func(key []byte) (Cipher, error) {
		if len(key) != chacha20poly1305.KeySize {
			return nil, fmt.Errorf("cipher: chacha20 per-frame requires %d-byte key", chacha20poly1305.KeySize)
		}
		return newPerFrameCipher(key, chacha20poly1305.NonceSize, func(k []byte) (cipher.AEAD, error) {
			return chacha20poly1305.New(k)
		})
	}
}

// XChaCha20Poly1305 returns a factory for XChaCha20-Poly1305.
func XChaCha20Poly1305() Factory {
	return func(key []byte) (Cipher, error) {
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, err
		}
		return &aeadCipher{aead: aead}, nil
	}
}

// XChaCha20Poly1305PerFrame derives a fresh key for every frame via HKDF.
func XChaCha20Poly1305PerFrame() Factory {
	return func(key []byte) (Cipher, error) {
		if len(key) != chacha20poly1305.KeySize {
			return nil, fmt.Errorf("cipher: xchacha per-frame requires %d-byte key", chacha20poly1305.KeySize)
		}
		return newPerFrameCipher(key, chacha20poly1305.NonceSizeX, func(k []byte) (cipher.AEAD, error) {
			return chacha20poly1305.NewX(k)
		})
	}
}

// AESGCMSIV returns a factory for AES-GCM-SIV (misuse-resistant AEAD).
func AESGCMSIV() Factory {
	return func(key []byte) (Cipher, error) {
		aead, err := siv.NewGCM(key)
		if err != nil {
			return nil, err
		}
		return &aeadCipher{aead: aead}, nil
	}
}

// perFrameCipher wraps a constructor and derives sub-keys per frame.
func newPerFrameCipher(root []byte, nonceSize int, constructor func([]byte) (cipher.AEAD, error)) (Cipher, error) {
	if nonceSize < 4 {
		return nil, fmt.Errorf("cipher: unsupported nonce size %d", nonceSize)
	}
	if len(root) == 0 {
		return nil, fmt.Errorf("cipher: empty root key")
	}
	sub, err := deriveSubKey(root, make([]byte, nonceSize))
	if err != nil {
		return nil, err
	}
	aead, err := constructor(sub)
	if err != nil {
		return nil, err
	}
	return &perFrameCipher{
		root:      slices.Clone(root),
		nonceSize: nonceSize,
		overhead:  aead.Overhead(),
		makeAEAD:  constructor,
	}, nil
}

type perFrameCipher struct {
	root      []byte
	nonceSize int
	overhead  int
	makeAEAD  func([]byte) (cipher.AEAD, error)
}

func (p *perFrameCipher) NonceSize() int { return p.nonceSize }

func (p *perFrameCipher) Overhead() int { return p.overhead }

func (p *perFrameCipher) Seal(dst, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(nonce) != p.nonceSize {
		return nil, fmt.Errorf("cipher: invalid nonce length")
	}
	key, err := deriveSubKey(p.root, nonce)
	if err != nil {
		return nil, err
	}
	aead, err := p.makeAEAD(key)
	if err != nil {
		return nil, err
	}
	zero := make([]byte, aead.NonceSize())
	return aead.Seal(dst, zero, plaintext, aad), nil
}

func (p *perFrameCipher) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != p.nonceSize {
		return nil, fmt.Errorf("cipher: invalid nonce length")
	}
	key, err := deriveSubKey(p.root, nonce)
	if err != nil {
		return nil, err
	}
	aead, err := p.makeAEAD(key)
	if err != nil {
		return nil, err
	}
	zero := make([]byte, aead.NonceSize())
	return aead.Open(dst, zero, ciphertext, aad)
}

func deriveSubKey(root, nonce []byte) ([]byte, error) {
	reader := hkdf.New(sha256.New, root, nil, nonce)
	key := make([]byte, len(root))
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}
