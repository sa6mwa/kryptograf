package keymgmt

import (
	"bytes"
	"encoding/pem"
	"testing"
)

func TestMintAndReconstructDEK(t *testing.T) {
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey() error = %v", err)
	}

	context := []byte("object-123")
	mat, err := MintDEK(root, context)
	if err != nil {
		t.Fatalf("MintDEK() error = %v", err)
	}

	recovered, err := ReconstructMaterial(root, context, mat.Descriptor)
	if err != nil {
		t.Fatalf("ReconstructMaterial() error = %v", err)
	}

	if !bytes.Equal(mat.Key.Bytes(), recovered.Key.Bytes()) {
		t.Fatalf("recovered DEK mismatch")
	}
}

func TestReconstructDEKContextMismatch(t *testing.T) {
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey() error = %v", err)
	}

	mat, err := MintDEK(root, []byte("context-a"))
	if err != nil {
		t.Fatalf("MintDEK() error = %v", err)
	}
	defer mat.Key.Zero()

	if _, err := ReconstructDEK(root, []byte("context-b"), mat.Descriptor); err == nil {
		t.Fatalf("expected context mismatch error")
	}
}

func TestDescriptorMarshalRoundTrip(t *testing.T) {
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey() error = %v", err)
	}
	mat, err := MintDEK(root, []byte("blob"))
	if err != nil {
		t.Fatalf("MintDEK() error = %v", err)
	}
	if err := (&mat.Descriptor).Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if mat.Descriptor.NonceBytes() != defaultNonceSize {
		t.Fatalf("expected nonce size %d, got %d", defaultNonceSize, mat.Descriptor.NonceBytes())
	}

	raw, err := mat.Descriptor.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	var out Descriptor
	if err := out.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if err := (&out).Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	if out != mat.Descriptor {
		t.Fatalf("descriptor mismatch after round trip")
	}
}

func TestPEMBundleRoundTrip(t *testing.T) {
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey error: %v", err)
	}
	mat, err := MintDEK(root, []byte("metadata"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}
	defer mat.Key.Zero()

	bundle := NewPEMBundle()
	// ensure existing blocks are preserved
	bundle.blocks = append(bundle.blocks, &pem.Block{Type: "CERTIFICATE", Bytes: []byte("dummy")})

	bundle.SetRootKey(root)
	if err := bundle.SetDescriptor("metadata", mat.Descriptor); err != nil {
		t.Fatalf("SetMetadataDescriptor error: %v", err)
	}

	out, err := bundle.Bytes()
	if err != nil {
		t.Fatalf("bundle.Bytes error: %v", err)
	}

	loaded, err := LoadPEMBundle(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("LoadPEMBundle error: %v", err)
	}

	root2, ok, err := loaded.RootKey()
	if err != nil {
		t.Fatalf("RootKey error: %v", err)
	}
	if !ok {
		t.Fatalf("expected root key in bundle")
	}
	if !bytes.Equal(root.Bytes(), root2.Bytes()) {
		t.Fatalf("root key mismatch after round trip")
	}

	desc2, ok, err := loaded.Descriptor("metadata")
	if err != nil {
		t.Fatalf("MetadataDescriptor error: %v", err)
	}
	if !ok {
		t.Fatalf("expected descriptor in bundle")
	}
	if err := (&desc2).Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if desc2 != mat.Descriptor {
		t.Fatalf("descriptor mismatch after round trip")
	}

	if len(loaded.Blocks()) != 3 {
		t.Fatalf("expected 3 blocks (certificate + root + descriptor), got %d", len(loaded.Blocks()))
	}
}

func TestMintDEKWithCustomNonce(t *testing.T) {
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey error: %v", err)
	}

	nonceSize := 24
	mat, err := MintDEKWithNonceSize(root, []byte("xchacha"), nonceSize)
	if err != nil {
		t.Fatalf("MintDEKWithNonceSize error: %v", err)
	}
	defer mat.Key.Zero()

	if err := (&mat.Descriptor).Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if mat.Descriptor.NonceBytes() != nonceSize {
		t.Fatalf("expected nonce size %d, got %d", nonceSize, mat.Descriptor.NonceBytes())
	}

	raw, err := mat.Descriptor.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error: %v", err)
	}

	var out Descriptor
	if err := out.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary() error: %v", err)
	}
	if err := (&out).Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if out.NonceBytes() != nonceSize {
		t.Fatalf("expected nonce size %d after unmarshal, got %d", nonceSize, out.NonceBytes())
	}
}

func TestHexHelpers(t *testing.T) {
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey error: %v", err)
	}
	rootHex := root.EncodeToHex()
	rootFromHex, err := RootKeyFromHex(rootHex)
	if err != nil {
		t.Fatalf("RootKeyFromHex error: %v", err)
	}
	if rootFromHex != root {
		t.Fatalf("root key mismatch after hex decode")
	}

	mat, err := MintDEK(root, []byte("ctx"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}
	dekHex := mat.Key.EncodeToHex()
	dekFromHex, err := DEKFromHex(dekHex)
	if err != nil {
		t.Fatalf("DEKFromHex error: %v", err)
	}
	if dekFromHex != mat.Key {
		t.Fatalf("DEK mismatch after hex decode")
	}

	descHex, err := mat.Descriptor.EncodeToHex()
	if err != nil {
		t.Fatalf("Descriptor EncodeToHex error: %v", err)
	}
	descFromHex, err := DescriptorFromHex(descHex)
	if err != nil {
		t.Fatalf("DescriptorFromHex error: %v", err)
	}
	if descFromHex != mat.Descriptor {
		t.Fatalf("descriptor mismatch after hex decode")
	}
}
