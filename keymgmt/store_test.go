package keymgmt

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDetectPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")

	pemBundle := NewPEMBundle()
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey error: %v", err)
	}
	pemBundle.SetRootKey(root)
	mat, err := MintDEK(root, []byte("metadata"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}
	if err := pemBundle.SetDescriptor("metadata", mat.Descriptor); err != nil {
		t.Fatalf("SetDescriptor error: %v", err)
	}
	data, err := pemBundle.Bytes()
	if err != nil {
		t.Fatalf("Bytes error: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	store, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if store.Format() != FormatPEM {
		t.Fatalf("expected PEM format, got %v", store.Format())
	}

	_, ok, err := store.Descriptor("metadata")
	if err != nil || !ok {
		t.Fatalf("Descriptor missing: %v", err)
	}

	newMat, err := MintDEKWithNonceSize(root, []byte("payload"), 16)
	if err != nil {
		t.Fatalf("MintDEKWithNonceSize error: %v", err)
	}
	if err := store.SetDescriptor("payload", newMat.Descriptor); err != nil {
		t.Fatalf("SetDescriptor error: %v", err)
	}

	if err := store.Commit(); err != nil {
		t.Fatalf("Commit error: %v", err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("Reload error: %v", err)
	}
	if desc2, ok, err := reloaded.Descriptor("payload"); err != nil || !ok || desc2 != newMat.Descriptor {
		t.Fatalf("descriptor not persisted")
	}
}

func TestLoadProtoIntoBytes(t *testing.T) {
	root, _ := GenerateRootKey()
	protoBundle := NewProtoBundle()
	protoBundle.SetRootKey(root)
	originalMat, err := MintDEK(root, []byte("ctx"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}
	if err := protoBundle.SetDescriptor("ctx", originalMat.Descriptor); err != nil {
		t.Fatalf("SetDescriptor error: %v", err)
	}
	data, err := protoBundle.Marshal()
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var out []byte
	store, err := LoadProtoInto(data, &out)
	if err != nil {
		t.Fatalf("LoadProtoInto error: %v", err)
	}
	if store.Format() != FormatProtobuf {
		t.Fatalf("expected protobuf format")
	}

	_, ok, err := store.Descriptor("ctx")
	if err != nil || !ok {
		t.Fatalf("Descriptor missing: %v", err)
	}

	updatedMat, err := MintDEKWithNonceSize(root, []byte("ctx"), 24)
	if err != nil {
		t.Fatalf("MintDEKWithNonceSize error: %v", err)
	}
	if err := store.SetDescriptor("ctx", updatedMat.Descriptor); err != nil {
		t.Fatalf("SetDescriptor error: %v", err)
	}
	if err := store.Commit(); err != nil {
		t.Fatalf("Commit error: %v", err)
	}

	loaded, err := LoadProto(out)
	if err != nil {
		t.Fatalf("LoadProto error: %v", err)
	}
	desc, ok, err := loaded.Descriptor("ctx")
	if err != nil || !ok || desc.NonceBytes() != updatedMat.Descriptor.NonceBytes() {
		t.Fatalf("descriptor not updated")
	}
}

func TestLoadFromReaderNoSink(t *testing.T) {
	pemBundle := NewPEMBundle()
	data, err := pemBundle.Bytes()
	if err != nil {
		t.Fatalf("Bytes error: %v", err)
	}

	store, err := Load(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if err := store.Commit(); err != nil {
		t.Fatalf("Commit without changes should be a noop: %v", err)
	}

	root, _ := GenerateRootKey()
	store.SetRootKey(root)
	if err := store.Commit(); !errors.Is(err, ErrNoSink) {
		t.Fatalf("expected ErrNoSink after modifications, got %v", err)
	}
}

func TestLoadCreatesMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "newbundle.pem")

	store, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	root, _ := GenerateRootKey()
	store.SetRootKey(root)
	if err := store.Commit(); err != nil {
		t.Fatalf("Commit error: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected file to be created: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected permissions 0600, got %v", info.Mode().Perm())
	}
}

func TestLoadAutoDetectProtoFromBytes(t *testing.T) {
	root, _ := GenerateRootKey()
	protoBundle := NewProtoBundle()
	protoBundle.SetRootKey(root)
	originalMat, err := MintDEK(root, []byte("ctx"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}
	if err := protoBundle.SetDescriptor("ctx", originalMat.Descriptor); err != nil {
		t.Fatalf("SetDescriptor error: %v", err)
	}
	data, err := protoBundle.Marshal()
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	store, err := Load(data)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if store.Format() != FormatProtobuf {
		t.Fatalf("expected FormatProtobuf, got %v", store.Format())
	}
	if desc, ok, err := store.Descriptor("ctx"); err != nil || !ok || desc.NonceBytes() != originalMat.Descriptor.NonceBytes() {
		t.Fatalf("expected descriptor")
	}
}

func TestLoadIntoWriterFromReader(t *testing.T) {
	pemBundle := NewPEMBundle()
	root, _ := GenerateRootKey()
	pemBundle.SetRootKey(root)
	data, err := pemBundle.Bytes()
	if err != nil {
		t.Fatalf("Bytes error: %v", err)
	}

	var out bytes.Buffer
	store, err := LoadInto(bytes.NewReader(data), &out)
	if err != nil {
		t.Fatalf("LoadInto error: %v", err)
	}
	if err := store.Commit(); err != nil {
		t.Fatalf("Commit without changes should succeed: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no data written on noop commit")
	}
	mat, err := MintDEK(root, []byte("ctx"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}
	store.SetDescriptor("ctx", mat.Descriptor)
	if err := store.Commit(); err != nil {
		t.Fatalf("Commit error: %v", err)
	}
	if out.Len() == 0 {
		t.Fatalf("expected writer to receive data")
	}
}

func TestLoadInvalidData(t *testing.T) {
	if _, err := Load([]byte("not a bundle")); err == nil {
		t.Fatalf("expected error for invalid payload")
	}
}
