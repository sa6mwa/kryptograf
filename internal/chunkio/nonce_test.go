package chunkio

import "testing"

func TestDeriveNonceSuccess(t *testing.T) {
	prefix := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	dst := make([]byte, len(prefix))
	if err := DeriveNonce(dst, prefix, 0x01020304); err != nil {
		t.Fatalf("DeriveNonce: %v", err)
	}
	// First bytes should equal prefix, last 4 bytes encode counter
	for i := 0; i < len(prefix)-4; i++ {
		if dst[i] != prefix[i] {
			t.Fatalf("prefix mismatch at %d", i)
		}
	}
	want := []byte{0x01, 0x02, 0x03, 0x04}
	for i, b := range want {
		if dst[len(dst)-4+i] != b {
			t.Fatalf("counter mismatch at %d: got %x want %x", i, dst[len(dst)-4+i], b)
		}
	}
}

func TestDeriveNonceRejectsShort(t *testing.T) {
	if err := DeriveNonce([]byte{1, 2, 3}, []byte{1, 2, 3}, 1); err == nil {
		t.Fatalf("expected error for short buffers")
	}
}

func TestDeriveNonceRejectsOverflow(t *testing.T) {
	prefix := make([]byte, 4)
	dst := make([]byte, 4)
	if err := DeriveNonce(dst, prefix, ^uint32(0)); err == nil {
		t.Fatalf("expected overflow error")
	}
}
