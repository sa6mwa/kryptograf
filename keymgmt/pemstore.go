package keymgmt

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"slices"
)

const (
	pemTypeRootKey    = "KRYPT-SYSTEM-ROOT-KEY"
	pemTypeDescriptor = "KRYPT-DESCRIPTOR"
	pemTypePBKDF2     = "KRYPT-PBKDF2-PARAMS"
)

// PEMBundle wraps a set of PEM blocks and exposes helpers for inserting and
// retrieving kryptograf-specific material while preserving all other blocks.
type PEMBundle struct {
	blocks []*pem.Block
}

// LoadPEMBundle reads all PEM blocks from r.
func LoadPEMBundle(r io.Reader) (*PEMBundle, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read PEM bundle: %w", err)
	}
	var blocks []*pem.Block
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("parse PEM bundle: invalid PEM data")
		}
		blocks = append(blocks, block)
		data = rest
	}
	return &PEMBundle{blocks: blocks}, nil
}

// NewPEMBundle returns an empty bundle.
func NewPEMBundle() *PEMBundle {
	return &PEMBundle{}
}

// Blocks returns a copy of the PEM blocks for inspection.
func (b *PEMBundle) Blocks() []*pem.Block {
	out := make([]*pem.Block, len(b.blocks))
	copy(out, b.blocks)
	return out
}

// RootKey retrieves the root key stored in the bundle, if present.
func (b *PEMBundle) RootKey() (RootKey, bool, error) {
	block := b.firstBlock(pemTypeRootKey)
	if block == nil {
		return RootKey{}, false, nil
	}
	if len(block.Bytes) != rootKeyBytes {
		return RootKey{}, false, fmt.Errorf("pem root key: expected %d bytes, got %d", rootKeyBytes, len(block.Bytes))
	}
	var key RootKey
	copy(key[:], block.Bytes)
	return key, true, nil
}

// SetRootKey inserts or replaces the root key block.
func (b *PEMBundle) SetRootKey(key RootKey) {
	block := &pem.Block{
		Type:    pemTypeRootKey,
		Headers: map[string]string{"Key-Length": fmt.Sprintf("%d", len(key))},
		Bytes:   slices.Clone(key[:]),
	}
	b.upsert(block)
}

// PBKDF2Params retrieves stored PBKDF2 parameters, if present.
func (b *PEMBundle) PBKDF2Params() (PBKDF2Params, bool, error) {
	block := b.firstBlock(pemTypePBKDF2)
	if block == nil {
		return PBKDF2Params{}, false, nil
	}
	params, err := UnmarshalPBKDF2Params(block.Bytes)
	if err != nil {
		return PBKDF2Params{}, false, fmt.Errorf("pem pbkdf2 params: %w", err)
	}
	return params, true, nil
}

// SetPBKDF2Params inserts or replaces stored PBKDF2 parameters.
func (b *PEMBundle) SetPBKDF2Params(params PBKDF2Params) error {
	data, err := MarshalPBKDF2Params(params)
	if err != nil {
		return err
	}
	id, err := hashIdentifier(params.Hash)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type: pemTypePBKDF2,
		Headers: map[string]string{
			"Hash":       id,
			"Iterations": fmt.Sprintf("%d", params.Iterations),
		},
		Bytes: data,
	}
	b.upsert(block)
	return nil
}

// Descriptor retrieves a descriptor stored under the provided name.
func (b *PEMBundle) Descriptor(name string) (Descriptor, bool, error) {
	block := b.firstDescriptorBlock(name)
	if block == nil {
		return Descriptor{}, false, nil
	}
	var desc Descriptor
	if err := desc.UnmarshalBinary(block.Bytes); err != nil {
		return Descriptor{}, false, fmt.Errorf("pem descriptor %q: %w", name, err)
	}
	return desc, true, nil
}

// SetDescriptor inserts or replaces the descriptor stored under name.
func (b *PEMBundle) SetDescriptor(name string, desc Descriptor) error {
	data, err := desc.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal descriptor: %w", err)
	}
	block := &pem.Block{
		Type:    pemTypeDescriptor,
		Headers: map[string]string{"Name": name, "Version": fmt.Sprintf("%d", desc.Version)},
		Bytes:   data,
	}
	b.upsertDescriptor(block)
	return nil
}

// Bytes renders the bundle back into PEM-encoded bytes.
func (b *PEMBundle) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	if err := b.Encode(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Encode writes the PEM bundle to w.
func (b *PEMBundle) Encode(w io.Writer) error {
	for _, block := range b.blocks {
		if err := pem.Encode(w, block); err != nil {
			return fmt.Errorf("encode PEM bundle: %w", err)
		}
	}
	return nil
}

func (b *PEMBundle) firstBlock(typ string) *pem.Block {
	for _, block := range b.blocks {
		if block.Type == typ {
			return block
		}
	}
	return nil
}

func (b *PEMBundle) firstDescriptorBlock(name string) *pem.Block {
	for _, block := range b.blocks {
		if block.Type != pemTypeDescriptor {
			continue
		}
		if block.Headers["Name"] == name {
			return block
		}
	}
	return nil
}

func (b *PEMBundle) upsert(block *pem.Block) {
	for i, existing := range b.blocks {
		if existing.Type == block.Type {
			b.blocks[i] = block
			return
		}
	}
	b.blocks = append(b.blocks, block)
}

func (b *PEMBundle) upsertDescriptor(block *pem.Block) {
	name := block.Headers["Name"]
	for i, existing := range b.blocks {
		if existing.Type == pemTypeDescriptor && existing.Headers["Name"] == name {
			b.blocks[i] = block
			return
		}
	}
	b.blocks = append(b.blocks, block)
}
