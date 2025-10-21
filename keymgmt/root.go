package keymgmt

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

const rootKeyBytes = 32

// RootKey represents a 256-bit symmetric key used to mint short-lived DEKs.
type RootKey [rootKeyBytes]byte

var (
	// ErrInvalidRootKeyLength indicates that the provided byte slice did not
	// contain exactly 32 bytes.
	ErrInvalidRootKeyLength = errors.New("kryptograf/keymgmt: invalid root key length")
)

// GenerateRootKey produces a new cryptographically secure 256-bit root key.
func GenerateRootKey() (RootKey, error) {
	var k RootKey
	if _, err := rand.Read(k[:]); err != nil {
		return RootKey{}, fmt.Errorf("generate root key: %w", err)
	}
	return k, nil
}

// MustGenerateRootKey is a helper for test scenarios and command line tools.
// It panics if key generation fails.
func MustGenerateRootKey() RootKey {
	k, err := GenerateRootKey()
	if err != nil {
		panic(err)
	}
	return k
}

// RootKeyFromBytes copies b into a RootKey. Returns an error if b does not
// contain exactly 32 bytes.
func RootKeyFromBytes(b []byte) (RootKey, error) {
	if len(b) != rootKeyBytes {
		return RootKey{}, fmt.Errorf("%w: got %d bytes", ErrInvalidRootKeyLength, len(b))
	}
	var k RootKey
	copy(k[:], b)
	return k, nil
}

// RootKeyFromBase64 decodes a base64 (raw, URL-safe) encoded string into a
// RootKey.
func RootKeyFromBase64(encoded string) (RootKey, error) {
	data, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return RootKey{}, fmt.Errorf("decode root key: %w", err)
	}
	return RootKeyFromBytes(data)
}

// EncodeToBase64 exports the root key as a base64 raw standard encoded string.
func (rk RootKey) EncodeToBase64() string {
	return base64.RawStdEncoding.EncodeToString(rk[:])
}

// EncodeToHex exports the root key as a hex string.
func (rk RootKey) EncodeToHex() string {
	return hex.EncodeToString(rk[:])
}

// RootKeyFromHex decodes a hex string into a RootKey.
func RootKeyFromHex(encoded string) (RootKey, error) {
	data, err := hex.DecodeString(encoded)
	if err != nil {
		return RootKey{}, fmt.Errorf("decode root key hex: %w", err)
	}
	return RootKeyFromBytes(data)
}

// Bytes returns the key material as a byte slice. The returned slice aliases
// the underlying array; callers must copy it if they intend to keep it.
func (rk RootKey) Bytes() []byte {
	return rk[:]
}

// Zero overwrites the key material with zeros.
func (rk *RootKey) Zero() {
	for i := range rk {
		rk[i] = 0
	}
}
