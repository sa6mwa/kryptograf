package keymgmt

import (
	"fmt"
	"io"
	"math"
	"slices"

	"google.golang.org/protobuf/proto"

	"pkt.systems/kryptograf/keymgmt/pb"
)

// ProtoBundle wraps the protobuf representation of a key bundle used by the
// storage backends.
type ProtoBundle struct {
	msg *pb.KeyBundle
}

// NewProtoBundle constructs an empty protobuf bundle ready to accept entries.
func NewProtoBundle() *ProtoBundle {
	return &ProtoBundle{msg: &pb.KeyBundle{Descriptors: make(map[string][]byte)}}
}

// LoadProtoBundle reads and unmarshals bundle data from the provided reader.
func LoadProtoBundle(r io.Reader) (*ProtoBundle, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read proto bundle: %w", err)
	}
	msg := &pb.KeyBundle{}
	if err := proto.Unmarshal(data, msg); err != nil {
		return nil, fmt.Errorf("unmarshal proto bundle: %w", err)
	}
	if msg.Descriptors == nil {
		msg.Descriptors = make(map[string][]byte)
	}
	return &ProtoBundle{msg: msg}, nil
}

// RootKey returns the stored root key, signalling whether it was present.
func (p *ProtoBundle) RootKey() (RootKey, bool, error) {
	keyBytes := p.msg.GetRootKey()
	if len(keyBytes) == 0 {
		return RootKey{}, false, nil
	}
	if len(keyBytes) != rootKeyBytes {
		return RootKey{}, false, fmt.Errorf("proto root key: expected %d bytes, got %d", rootKeyBytes, len(keyBytes))
	}
	var key RootKey
	copy(key[:], keyBytes)
	return key, true, nil
}

// SetRootKey overwrites the stored root key in the bundle.
func (p *ProtoBundle) SetRootKey(key RootKey) {
	p.msg.RootKey = append(p.msg.RootKey[:0], key[:]...)
}

// PBKDF2Params retrieves stored PBKDF2 parameters, if present.
func (p *ProtoBundle) PBKDF2Params() (PBKDF2Params, bool, error) {
	record := p.msg.GetPbkdf2Params()
	if record == nil {
		return PBKDF2Params{}, false, nil
	}
	params, err := pbkdf2ParamsFromProto(record)
	if err != nil {
		return PBKDF2Params{}, false, err
	}
	return params, true, nil
}

// SetPBKDF2Params overwrites the stored PBKDF2 parameters in the bundle.
func (p *ProtoBundle) SetPBKDF2Params(params PBKDF2Params) error {
	record, err := pbkdf2ParamsToProto(params)
	if err != nil {
		return err
	}
	p.msg.Pbkdf2Params = record
	return nil
}

// Descriptor retrieves the descriptor stored under the supplied name.
func (p *ProtoBundle) Descriptor(name string) (Descriptor, bool, error) {
	data, ok := p.msg.Descriptors[name]
	if !ok {
		return Descriptor{}, false, nil
	}
	var desc Descriptor
	if err := desc.UnmarshalBinary(data); err != nil {
		return Descriptor{}, false, fmt.Errorf("proto descriptor %q: %w", name, err)
	}
	return desc, true, nil
}

// SetDescriptor inserts or replaces the descriptor associated with name.
func (p *ProtoBundle) SetDescriptor(name string, desc Descriptor) error {
	data, err := desc.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal descriptor: %w", err)
	}
	if p.msg.Descriptors == nil {
		p.msg.Descriptors = make(map[string][]byte)
	}
	p.msg.Descriptors[name] = data
	return nil
}

// Marshal serialises the bundle into protobuf bytes.
func (p *ProtoBundle) Marshal() ([]byte, error) {
	return proto.Marshal(p.msg)
}

// WriteTo serialises the bundle and writes it to w.
func (p *ProtoBundle) WriteTo(w io.Writer) error {
	data, err := p.Marshal()
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write proto bundle: %w", err)
	}
	return nil
}

// Bytes implements the backend interface expected by Store.
func (p *ProtoBundle) Bytes() ([]byte, error) {
	return p.Marshal()
}

func pbkdf2ParamsToProto(params PBKDF2Params) (*pb.PBKDF2Params, error) {
	id, err := hashIdentifier(params.Hash)
	if err != nil {
		return nil, err
	}
	if params.Iterations <= 0 {
		return nil, fmt.Errorf("%w: iterations must be > 0", ErrInvalidPBKDF2Params)
	}
	if params.Iterations > math.MaxInt32 {
		return nil, fmt.Errorf("%w: iterations overflow", ErrInvalidPBKDF2Params)
	}
	if params.KeyLength != rootKeyBytes {
		return nil, fmt.Errorf("%w: expected %d-byte key, got %d", ErrInvalidPBKDF2Params, rootKeyBytes, params.KeyLength)
	}
	if params.KeyLength > math.MaxInt32 {
		return nil, fmt.Errorf("%w: key length overflow", ErrInvalidPBKDF2Params)
	}
	if len(params.Salt) == 0 {
		return nil, fmt.Errorf("%w: missing salt", ErrInvalidPBKDF2Params)
	}
	return &pb.PBKDF2Params{
		Hash:       id,
		Iterations: int32(params.Iterations),
		Salt:       slices.Clone(params.Salt),
		KeyLength:  int32(params.KeyLength),
	}, nil
}

func pbkdf2ParamsFromProto(record *pb.PBKDF2Params) (PBKDF2Params, error) {
	if record == nil {
		return PBKDF2Params{}, fmt.Errorf("%w: nil proto record", ErrInvalidPBKDF2Params)
	}
	params := PBKDF2Params{
		Hash:       hashFromIdentifier(record.GetHash()),
		Iterations: int(record.GetIterations()),
		Salt:       slices.Clone(record.GetSalt()),
		KeyLength:  int(record.GetKeyLength()),
	}
	if params.Hash == nil {
		return PBKDF2Params{}, fmt.Errorf("%w: %q", ErrUnsupportedPBKDF2Hash, record.GetHash())
	}
	if params.Iterations <= 0 {
		return PBKDF2Params{}, fmt.Errorf("%w: iterations must be > 0", ErrInvalidPBKDF2Params)
	}
	if params.KeyLength != rootKeyBytes {
		return PBKDF2Params{}, fmt.Errorf("%w: expected %d-byte key, got %d", ErrInvalidPBKDF2Params, rootKeyBytes, params.KeyLength)
	}
	if len(params.Salt) == 0 {
		return PBKDF2Params{}, fmt.Errorf("%w: missing salt", ErrInvalidPBKDF2Params)
	}
	return params, nil
}
