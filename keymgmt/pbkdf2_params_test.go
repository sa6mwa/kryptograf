package keymgmt

import (
	"bytes"
	"testing"
)

func TestMarshalPBKDF2ParamsRoundTrip(t *testing.T) {
	params, err := GeneratePBKDF2Params()
	if err != nil {
		t.Fatalf("GeneratePBKDF2Params error: %v", err)
	}
	data, err := MarshalPBKDF2Params(params)
	if err != nil {
		t.Fatalf("MarshalPBKDF2Params error: %v", err)
	}
	restored, err := UnmarshalPBKDF2Params(data)
	if err != nil {
		t.Fatalf("UnmarshalPBKDF2Params error: %v", err)
	}
	if !equalPBKDF2Params(params, restored) {
		t.Fatalf("params mismatch after round trip")
	}
}

func TestStoreEnsurePBKDF2ParamsPEM(t *testing.T) {
	var buf []byte
	store, err := LoadPEMInto([]byte(nil), &buf)
	if err != nil {
		t.Fatalf("LoadPEMInto error: %v", err)
	}
	params, err := store.EnsurePBKDF2Params()
	if err != nil {
		t.Fatalf("EnsurePBKDF2Params error: %v", err)
	}
	if err := store.Commit(); err != nil {
		t.Fatalf("Commit error: %v", err)
	}
	reloaded, err := LoadPEM(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("LoadPEM error: %v", err)
	}
	got, ok, err := reloaded.PBKDF2Params()
	if err != nil {
		t.Fatalf("PBKDF2Params error: %v", err)
	}
	if !ok {
		t.Fatalf("expected PBKDF2 params in store")
	}
	if !equalPBKDF2Params(params, got) {
		t.Fatalf("params mismatch after reload")
	}
	ensured, err := reloaded.EnsurePBKDF2Params()
	if err != nil {
		t.Fatalf("EnsurePBKDF2Params (reload) error: %v", err)
	}
	if !equalPBKDF2Params(got, ensured) {
		t.Fatalf("EnsurePBKDF2Params should return existing params")
	}
}

func TestStoreSetPBKDF2ParamsProto(t *testing.T) {
	params := MustGeneratePBKDF2Params()
	var buf []byte
	store, err := LoadProtoInto([]byte(nil), &buf)
	if err != nil {
		t.Fatalf("LoadProtoInto error: %v", err)
	}
	if err := store.SetPBKDF2Params(params); err != nil {
		t.Fatalf("SetPBKDF2Params error: %v", err)
	}
	if err := store.Commit(); err != nil {
		t.Fatalf("Commit error: %v", err)
	}
	reloaded, err := LoadProto(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("LoadProto error: %v", err)
	}
	got, ok, err := reloaded.PBKDF2Params()
	if err != nil {
		t.Fatalf("PBKDF2Params error: %v", err)
	}
	if !ok {
		t.Fatalf("expected PBKDF2 params in proto bundle")
	}
	if !equalPBKDF2Params(params, got) {
		t.Fatalf("params mismatch after proto reload")
	}
}
