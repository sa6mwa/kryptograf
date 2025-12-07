package chunkio

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeHeaderRoundTrip(t *testing.T) {
	h := Header{
		Version: FrameVersion(),
		Flags:   0x2,
		Counter: 42,
		Payload: 1024,
	}
	buf := make([]byte, FrameHeaderSize)
	EncodeHeader(buf, h)

	got, err := DecodeHeader(buf)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if got != h {
		t.Fatalf("header mismatch: %+v != %+v", got, h)
	}
}

func TestFinalFlagAndMark(t *testing.T) {
	var h Header
	if FinalFlag(h) {
		t.Fatalf("expected FinalFlag false")
	}
	MarkFinal(&h)
	if !FinalFlag(h) {
		t.Fatalf("expected FinalFlag true after MarkFinal")
	}
}

func TestNextCounterOverflow(t *testing.T) {
	if _, err := NextCounter(^uint32(0)); err == nil {
		t.Fatalf("expected overflow error")
	}
}

func TestDecodeHeaderRejectsShortBuffer(t *testing.T) {
	_, err := DecodeHeader([]byte{1, 2, 3})
	if err == nil {
		t.Fatalf("expected error for short buffer")
	}
}

func TestEncodeHeaderPanicOnShortBuf(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic for short buffer")
		}
	}()
	EncodeHeader([]byte{0}, Header{})
}

func TestDecodeHeaderRejectsVersionMismatch(t *testing.T) {
	buf := bytes.Repeat([]byte{0}, FrameHeaderSize)
	buf[0] = 99 // unknown version
	if _, err := DecodeHeader(buf); err == nil {
		t.Fatalf("expected version mismatch error")
	}
}
