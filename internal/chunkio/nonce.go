package chunkio

import (
	"encoding/binary"
	"fmt"
)

const (
	// DefaultNonceBytes is the standard nonce length used when minting DEKs.
	DefaultNonceBytes = 12
	// MinNonceBytes is the minimum nonce length allowed by the frame format.
	MinNonceBytes = 4
)

// DeriveNonce encodes the frame counter into the trailing four bytes of dst.
// dst and prefix must be the same length and at least four bytes long.
func DeriveNonce(dst, prefix []byte, counter uint32) error {
	if len(prefix) < MinNonceBytes || len(dst) < len(prefix) {
		return fmt.Errorf("kryptograf/chunkio: invalid nonce buffer")
	}
	if counter == ^uint32(0) {
		return fmt.Errorf("kryptograf/chunkio: counter overflow")
	}
	copy(dst, prefix)
	binary.BigEndian.PutUint32(dst[len(prefix)-4:], counter)
	return nil
}
