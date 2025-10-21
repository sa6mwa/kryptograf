package keymgmt

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Format enumerates the supported bundle encodings.
type Format int

// Supported store formats for serialising key bundles.
const (
	FormatUnknown Format = iota
	FormatPEM
	FormatProtobuf
)

// ErrNoSink indicates that the store was created without a destination for
// persisting changes.
var ErrNoSink = errors.New("kryptograf/keymgmt: no sink configured for commit")

// Store exposes a unified API for reading/writing root keys, PBKDF2 parameters,
// and descriptors regardless of the underlying storage format (PEM, protobuf,
// etc.).
type Store interface {
	RootKey() (key RootKey, found bool, err error)
	SetRootKey(RootKey)
	EnsureRootKey() (RootKey, error)
	PBKDF2Params() (PBKDF2Params, bool, error)
	SetPBKDF2Params(PBKDF2Params) error
	EnsurePBKDF2Params() (PBKDF2Params, error)
	Descriptor(name string) (desc Descriptor, found bool, err error)
	SetDescriptor(name string, desc Descriptor) error
	EnsureDescriptor(name string, root RootKey, context []byte) (Material, error)
	Bytes() ([]byte, error)
	Commit() error
	Format() Format
}

type backend interface {
	RootKey() (key RootKey, found bool, err error)
	SetRootKey(RootKey)
	PBKDF2Params() (PBKDF2Params, bool, error)
	SetPBKDF2Params(PBKDF2Params) error
	Descriptor(name string) (desc Descriptor, found bool, err error)
	SetDescriptor(name string, desc Descriptor) error
	Bytes() ([]byte, error)
}

type sinkKind int

const (
	sinkNone sinkKind = iota
	sinkPath
	sinkWriter
	sinkBytes
)

type sinkTarget struct {
	kind   sinkKind
	path   string
	writer io.Writer
	bytes  *[]byte
}

type store struct {
	backend backend
	sink    sinkTarget
	format  Format
	dirty   bool
}

func (s *store) RootKey() (RootKey, bool, error) {
	return s.backend.RootKey()
}

func (s *store) SetRootKey(key RootKey) {
	if current, ok, err := s.backend.RootKey(); err == nil && ok && current == key {
		return
	}
	s.backend.SetRootKey(key)
	s.dirty = true
}

func (s *store) EnsureRootKey() (RootKey, error) {
	key, ok, err := s.backend.RootKey()
	if err != nil {
		return RootKey{}, err
	}
	if ok {
		return key, nil
	}
	key = MustGenerateRootKey()
	s.backend.SetRootKey(key)
	s.dirty = true
	return key, nil
}

func (s *store) PBKDF2Params() (PBKDF2Params, bool, error) {
	return s.backend.PBKDF2Params()
}

func (s *store) SetPBKDF2Params(params PBKDF2Params) error {
	current, ok, err := s.backend.PBKDF2Params()
	if err != nil {
		return err
	}
	if ok && equalPBKDF2Params(current, params) {
		return nil
	}
	if err := s.backend.SetPBKDF2Params(params); err != nil {
		return err
	}
	s.dirty = true
	return nil
}

func (s *store) EnsurePBKDF2Params() (PBKDF2Params, error) {
	params, ok, err := s.backend.PBKDF2Params()
	if err != nil {
		return PBKDF2Params{}, err
	}
	if ok {
		return params, nil
	}
	params, err = GeneratePBKDF2Params()
	if err != nil {
		return PBKDF2Params{}, err
	}
	if err := s.backend.SetPBKDF2Params(params); err != nil {
		return PBKDF2Params{}, err
	}
	s.dirty = true
	return params, nil
}

func (s *store) Descriptor(name string) (Descriptor, bool, error) {
	return s.backend.Descriptor(name)
}

func (s *store) SetDescriptor(name string, desc Descriptor) error {
	current, ok, err := s.backend.Descriptor(name)
	if err != nil {
		return err
	}
	if ok && current == desc {
		return nil
	}
	if err := s.backend.SetDescriptor(name, desc); err != nil {
		return err
	}
	s.dirty = true
	return nil
}

func (s *store) EnsureDescriptor(name string, root RootKey, context []byte) (Material, error) {
	desc, ok, err := s.backend.Descriptor(name)
	if err != nil {
		return Material{}, err
	}
	if ok {
		return ReconstructMaterial(root, context, desc)
	}
	mat, err := MintDEK(root, context)
	if err != nil {
		return Material{}, err
	}
	if err := s.backend.SetDescriptor(name, mat.Descriptor); err != nil {
		return Material{}, err
	}
	s.dirty = true
	return mat, nil
}

func (s *store) Bytes() ([]byte, error) {
	return s.backend.Bytes()
}

func (s *store) Format() Format {
	return s.format
}

func (s *store) Commit() error {
	if !s.dirty {
		return nil
	}
	data, err := s.backend.Bytes()
	if err != nil {
		return err
	}

	var commitErr error
	switch s.sink.kind {
	case sinkPath:
		commitErr = os.WriteFile(s.sink.path, data, 0o600)
	case sinkWriter:
		if _, err := s.sink.writer.Write(data); err != nil {
			commitErr = fmt.Errorf("write bundle: %w", err)
		}
	case sinkBytes:
		if s.sink.bytes == nil {
			commitErr = ErrNoSink
			break
		}
		buf := *s.sink.bytes
		buf = append(buf[:0], data...)
		*s.sink.bytes = buf
	default:
		commitErr = ErrNoSink
	}
	if commitErr != nil {
		return commitErr
	}
	s.dirty = false
	return nil
}

// Load ingests bundle data from any supported source. If the source is a file
// path, the store will default to writing back to that file on Commit.
func Load(from any) (Store, error) {
	return loadInternal(from, sinkTarget{}, FormatUnknown, false)
}

// LoadInto ingests bundle data from a source while explicitly specifying the
// destination sink that Commit should write to.
func LoadInto(from, to any) (Store, error) {
	sink, err := makeSink(to)
	if err != nil {
		return nil, err
	}
	return loadInternal(from, sink, FormatUnknown, false)
}

// LoadPEM forces PEM format regardless of content.
func LoadPEM(from any) (Store, error) {
	return loadInternal(from, sinkTarget{}, FormatPEM, true)
}

// LoadPEMInto forces PEM format and writes to the provided sink on Commit.
func LoadPEMInto(from, to any) (Store, error) {
	sink, err := makeSink(to)
	if err != nil {
		return nil, err
	}
	return loadInternal(from, sink, FormatPEM, true)
}

// LoadProto forces protobuf format regardless of content.
func LoadProto(from any) (Store, error) {
	return loadInternal(from, sinkTarget{}, FormatProtobuf, true)
}

// LoadProtoInto forces protobuf format for the provided sink.
func LoadProtoInto(from, to any) (Store, error) {
	sink, err := makeSink(to)
	if err != nil {
		return nil, err
	}
	return loadInternal(from, sink, FormatProtobuf, true)
}

func loadInternal(from any, sink sinkTarget, forced Format, force bool) (Store, error) {
	data, defaultSink, formatHint, err := readSource(from)
	if err != nil {
		return nil, err
	}
	if sink.kind == sinkNone {
		sink = defaultSink
	}

	format := forced
	if format == FormatUnknown {
		format = formatHint
	}

	backend, formatDetected, err := buildBackend(data, format, force)
	if err != nil {
		return nil, err
	}

	if format == FormatUnknown {
		format = formatDetected
	}

	return &store{
		backend: backend,
		sink:    sink,
		format:  format,
	}, nil
}

func readSource(src any) ([]byte, sinkTarget, Format, error) {
	switch v := src.(type) {
	case string:
		if v == "" {
			return nil, sinkTarget{}, FormatUnknown, fmt.Errorf("kryptograf/keymgmt: empty source path")
		}
		data, err := os.ReadFile(v)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				data = nil
			} else {
				return nil, sinkTarget{}, FormatUnknown, fmt.Errorf("read source %q: %w", v, err)
			}
		}
		return data, sinkTarget{kind: sinkPath, path: v}, guessFormatFromPath(v), nil
	case []byte:
		data := slices.Clone(v)
		return data, sinkTarget{}, FormatUnknown, nil
	case io.Reader:
		data, err := io.ReadAll(v)
		if err != nil {
			return nil, sinkTarget{}, FormatUnknown, fmt.Errorf("read source: %w", err)
		}
		return data, sinkTarget{}, FormatUnknown, nil
	default:
		return nil, sinkTarget{}, FormatUnknown, fmt.Errorf("unsupported source type %T", src)
	}
}

func makeSink(to any) (sinkTarget, error) {
	switch v := to.(type) {
	case string:
		if v == "" {
			return sinkTarget{}, fmt.Errorf("kryptograf/keymgmt: empty destination path")
		}
		return sinkTarget{kind: sinkPath, path: v}, nil
	case *[]byte:
		if v == nil {
			return sinkTarget{}, fmt.Errorf("kryptograf/keymgmt: nil *[]byte sink")
		}
		return sinkTarget{kind: sinkBytes, bytes: v}, nil
	case io.Writer:
		return sinkTarget{kind: sinkWriter, writer: v}, nil
	default:
		return sinkTarget{}, fmt.Errorf("unsupported sink type %T", to)
	}
}

func guessFormatFromPath(path string) Format {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pem", ".crt", ".key":
		return FormatPEM
	case ".pb", ".bin", ".proto":
		return FormatProtobuf
	default:
		return FormatUnknown
	}
}

func buildBackend(data []byte, desired Format, force bool) (backend, Format, error) {
	if len(data) > 0 && !force {
		if format, backend, err := detectBackend(data); err == nil {
			return backend, format, nil
		}
	}

	format := desired
	if format == FormatUnknown {
		format = FormatPEM
	}

	switch format {
	case FormatPEM:
		if len(data) == 0 {
			return NewPEMBundle(), FormatPEM, nil
		}
		bundle, err := LoadPEMBundle(bytes.NewReader(data))
		if err != nil {
			return nil, FormatUnknown, fmt.Errorf("load PEM bundle: %w", err)
		}
		return bundle, FormatPEM, nil
	case FormatProtobuf:
		if len(data) == 0 {
			return NewProtoBundle(), FormatProtobuf, nil
		}
		bundle, err := LoadProtoBundle(bytes.NewReader(data))
		if err != nil {
			return nil, FormatUnknown, fmt.Errorf("load proto bundle: %w", err)
		}
		return bundle, FormatProtobuf, nil
	default:
		return nil, FormatUnknown, fmt.Errorf("kryptograf/keymgmt: unsupported format %v", format)
	}
}

func detectBackend(data []byte) (Format, backend, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return FormatUnknown, nil, fmt.Errorf("empty data")
	}

	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		if bundle, err := LoadPEMBundle(bytes.NewReader(data)); err == nil {
			return FormatPEM, bundle, nil
		}
	}

	if bundle, err := LoadProtoBundle(bytes.NewReader(data)); err == nil {
		return FormatProtobuf, bundle, nil
	}

	if bundle, err := LoadPEMBundle(bytes.NewReader(data)); err == nil {
		return FormatPEM, bundle, nil
	}

	return FormatUnknown, nil, fmt.Errorf("kryptograf/keymgmt: unrecognised bundle format")
}
