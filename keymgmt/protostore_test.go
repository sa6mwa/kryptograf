package keymgmt

import (
	"bytes"
	"testing"
)

func TestProtoBundleRoundTrip(t *testing.T) {
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey error: %v", err)
	}
	mat, err := MintDEK(root, []byte("proto"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}

	bundle := NewProtoBundle()
	bundle.SetRootKey(root)
	if err := bundle.SetDescriptor("metadata", mat.Descriptor); err != nil {
		t.Fatalf("SetDescriptor error: %v", err)
	}

	data, err := bundle.Marshal()
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	loaded, err := LoadProtoBundle(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("LoadProtoBundle error: %v", err)
	}

	root2, ok, err := loaded.RootKey()
	if err != nil {
		t.Fatalf("RootKey error: %v", err)
	}
	if !ok {
		t.Fatalf("expected root key")
	}
	if !bytes.Equal(root.Bytes(), root2.Bytes()) {
		t.Fatalf("root key mismatch")
	}

	desc2, ok, err := loaded.Descriptor("metadata")
	if err != nil {
		t.Fatalf("Descriptor error: %v", err)
	}
	if !ok {
		t.Fatalf("expected descriptor")
	}
	if desc2 != mat.Descriptor {
		t.Fatalf("descriptor mismatch")
	}
}
