package keymgmt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	dekBytes           = 32
	descriptorVersion1 = 1
	descriptorVersion2 = 2
	defaultNonceSize   = 12
	maxNonceSize       = 32
	saltBytes          = 32
)

// DEK represents a 256-bit data-encryption key derived from a root key.
type DEK [dekBytes]byte

// Descriptor contains the metadata required to reconstruct a DEK.
type Descriptor struct {
	Version       uint8
	HKDFHash      uint8
	NonceSize     uint8
	Salt          [saltBytes]byte
	Nonce         [maxNonceSize]byte
	ContextDigest [sha256.Size]byte
}

// Ensure Descriptor implements encoding interfaces for easy persistence.
var (
	_ encoding.BinaryMarshaler   = Descriptor{}
	_ encoding.BinaryUnmarshaler = (*Descriptor)(nil)
)

var (
	// ErrDescriptorVersion indicates an unknown descriptor version.
	ErrDescriptorVersion = errors.New("kryptograf/keymgmt: unsupported descriptor version")
	// ErrDescriptorHash indicates an unsupported HKDF hash identifier.
	ErrDescriptorHash = errors.New("kryptograf/keymgmt: unsupported HKDF hash")
	// ErrContextMismatch indicates that the caller-supplied context bytes do
	// not match the descriptor's context digest.
	ErrContextMismatch = errors.New("kryptograf/keymgmt: context digest mismatch")
)

const (
	hkdfSHA256 uint8 = 1
)

// MintDEK derives a short-lived DEK using HKDF-SHA256. The caller supplies the
// contextual bytes that should bind the DEK (for example, object identifiers or
// deployment-specific entropy).
func MintDEK(root RootKey, context []byte) (Material, error) {
	return MintDEKWithNonceSize(root, context, defaultNonceSize)
}

// MintDEKWithNonceSize derives a DEK and descriptor with the specified nonce size.
// nonceSize must be between 4 and maxNonceSize bytes.
func MintDEKWithNonceSize(root RootKey, context []byte, nonceSize int) (Material, error) {
	if nonceSize < 4 || nonceSize > maxNonceSize {
		return Material{}, fmt.Errorf("mint DEK: invalid nonce size %d", nonceSize)
	}

	var salt [saltBytes]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return Material{}, fmt.Errorf("generate DEK salt: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if nonceSize > 4 {
		if _, err := rand.Read(nonce[:nonceSize-4]); err != nil {
			return Material{}, fmt.Errorf("generate DEK nonce: %w", err)
		}
	}
	// Reserve last 4 bytes for the stream counter.
	copy(nonce[nonceSize-4:], make([]byte, 4))

	digest := sha256.Sum256(context)
	key, err := deriveDEK(root, salt[:], context)
	if err != nil {
		return Material{}, err
	}

	desc := Descriptor{
		Version:       descriptorVersion2,
		HKDFHash:      hkdfSHA256,
		NonceSize:     uint8(nonceSize),
		Salt:          salt,
		ContextDigest: digest,
	}
	copy(desc.Nonce[:nonceSize], nonce)

	return Material{Key: key, Descriptor: desc}, nil
}

// ReconstructDEK reproduces a previously minted DEK using the stored descriptor
// and the original context bytes.
func ReconstructDEK(root RootKey, context []byte, desc Descriptor) (DEK, error) {
	if err := (&desc).Validate(); err != nil {
		return DEK{}, err
	}
	digest := sha256.Sum256(context)
	if !hmac.Equal(desc.ContextDigest[:], digest[:]) {
		return DEK{}, ErrContextMismatch
	}

	key, err := deriveDEK(root, desc.Salt[:], context)
	if err != nil {
		return DEK{}, err
	}
	return key, nil
}

// ReconstructMaterial rebuilds the DEK and returns it alongside the supplied descriptor.
func ReconstructMaterial(root RootKey, context []byte, desc Descriptor) (Material, error) {
	key, err := ReconstructDEK(root, context, desc)
	if err != nil {
		return Material{}, err
	}
	return Material{Key: key, Descriptor: desc}, nil
}

func deriveDEK(root RootKey, salt, context []byte) (DEK, error) {
	reader := hkdf.New(sha256.New, root[:], salt, context)
	var key DEK
	if _, err := io.ReadFull(reader, key[:]); err != nil {
		return DEK{}, fmt.Errorf("derive DEK: %w", err)
	}
	return key, nil
}

// Validate checks whether the descriptor uses a supported version/hash pair.
func (d *Descriptor) Validate() error {
	switch d.Version {
	case descriptorVersion1:
		d.NonceSize = defaultNonceSize
	case descriptorVersion2:
		if d.NonceSize == 0 {
			return fmt.Errorf("kryptograf/keymgmt: descriptor missing nonce size")
		}
	default:
		return ErrDescriptorVersion
	}
	if d.HKDFHash != hkdfSHA256 {
		return ErrDescriptorHash
	}
	if d.NonceSize < 4 || d.NonceSize > maxNonceSize {
		return fmt.Errorf("kryptograf/keymgmt: invalid nonce size %d", d.NonceSize)
	}
	return nil
}

// EncodeToHex renders the descriptor as a hex string.
func (d Descriptor) EncodeToHex() (string, error) {
	data, err := d.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

// DescriptorFromHex decodes a hex string into a Descriptor.
func DescriptorFromHex(encoded string) (Descriptor, error) {
	data, err := hex.DecodeString(encoded)
	if err != nil {
		return Descriptor{}, fmt.Errorf("decode descriptor hex: %w", err)
	}
	var desc Descriptor
	if err := desc.UnmarshalBinary(data); err != nil {
		return Descriptor{}, err
	}
	return desc, nil
}

// Bytes exposes the DEK key material. The returned slice aliases the internal
// array and becomes invalid if Zero is called.
func (d DEK) Bytes() []byte {
	return d[:]
}

// EncodeToHex exports the DEK as a hex string.
func (d DEK) EncodeToHex() string {
	return hex.EncodeToString(d[:])
}

// DEKFromHex decodes a hex string into a DEK.
func DEKFromHex(encoded string) (DEK, error) {
	data, err := hex.DecodeString(encoded)
	if err != nil {
		return DEK{}, fmt.Errorf("decode DEK hex: %w", err)
	}
	if len(data) != dekBytes {
		return DEK{}, fmt.Errorf("decode DEK hex: expected %d bytes, got %d", dekBytes, len(data))
	}
	var d DEK
	copy(d[:], data)
	return d, nil
}

// Zero overwrites the DEK material with zeros.
func (d *DEK) Zero() {
	for i := range d {
		d[i] = 0
	}
}

// MarshalBinary encodes the descriptor into a stable binary representation.
func (d Descriptor) MarshalBinary() ([]byte, error) {
	switch d.Version {
	case descriptorVersion1:
		buf := make([]byte, 0, 2+saltBytes+defaultNonceSize+sha256.Size)
		buf = append(buf, byte(d.Version), byte(d.HKDFHash))
		buf = append(buf, d.Salt[:]...)
		buf = append(buf, d.Nonce[:defaultNonceSize]...)
		buf = append(buf, d.ContextDigest[:]...)
		return buf, nil
	case descriptorVersion2:
		nonceSize := int(d.NonceSize)
		if nonceSize == 0 {
			return nil, fmt.Errorf("marshal descriptor: nonce size not set")
		}
		buf := make([]byte, 0, 3+saltBytes+nonceSize+sha256.Size)
		buf = append(buf, byte(d.Version), byte(d.HKDFHash), byte(nonceSize))
		buf = append(buf, d.Salt[:]...)
		buf = append(buf, d.Nonce[:nonceSize]...)
		buf = append(buf, d.ContextDigest[:]...)
		return buf, nil
	default:
		return nil, ErrDescriptorVersion
	}
}

// UnmarshalBinary decodes the descriptor from its binary representation.
func (d *Descriptor) UnmarshalBinary(data []byte) error {
	if len(data) < 2+saltBytes+sha256.Size {
		return fmt.Errorf("decode descriptor: buffer too small")
	}
	version := uint8(data[0])
	hash := uint8(data[1])
	offset := 2

	switch version {
	case descriptorVersion1:
		expectedLen := 2 + saltBytes + defaultNonceSize + sha256.Size
		if len(data) != expectedLen {
			return fmt.Errorf("decode descriptor: expected %d bytes, got %d", expectedLen, len(data))
		}
		d.Version = version
		d.HKDFHash = hash
		copy(d.Salt[:], data[offset:offset+saltBytes])
		offset += saltBytes
		copy(d.Nonce[:defaultNonceSize], data[offset:offset+defaultNonceSize])
		d.NonceSize = defaultNonceSize
		offset += defaultNonceSize
		copy(d.ContextDigest[:], data[offset:])
		return nil
	case descriptorVersion2:
		if len(data) < 3+saltBytes+sha256.Size {
			return fmt.Errorf("decode descriptor: buffer too small for v2")
		}
		nonceSize := int(data[2])
		offset++ // to account for nonce size byte
		expectedLen := 3 + saltBytes + nonceSize + sha256.Size
		if len(data) != expectedLen {
			return fmt.Errorf("decode descriptor: expected %d bytes, got %d", expectedLen, len(data))
		}
		if nonceSize < 4 || nonceSize > maxNonceSize {
			return fmt.Errorf("decode descriptor: invalid nonce size %d", nonceSize)
		}
		d.Version = version
		d.HKDFHash = hash
		d.NonceSize = uint8(nonceSize)
		copy(d.Salt[:], data[offset:offset+saltBytes])
		offset += saltBytes
		copy(d.Nonce[:nonceSize], data[offset:offset+nonceSize])
		offset += nonceSize
		copy(d.ContextDigest[:], data[offset:])
		return nil
	default:
		return ErrDescriptorVersion
	}
}

// NonceBytes returns the number of bytes in the stored nonce prefix.
func (d Descriptor) NonceBytes() int {
	if d.NonceSize == 0 {
		return defaultNonceSize
	}
	return int(d.NonceSize)
}

// NoncePrefix exposes the nonce prefix as a slice sized to NonceBytes().
func (d Descriptor) NoncePrefix() []byte {
	return d.Nonce[:d.NonceBytes()]
}
