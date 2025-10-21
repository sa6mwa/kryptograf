package chunkio

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// FrameHeaderSize is the number of bytes in every frame header.
	FrameHeaderSize = 10

	frameVersion1   = 1
	flagFinalFrame  = 1 << 0
	maxFrameCounter = ^uint32(0)
)

// Header models the metadata prefix for every encrypted frame.
type Header struct {
	Version uint8
	Flags   uint8
	Counter uint32
	Payload uint32
}

// ErrVersionMismatch indicates that the frame version is unsupported.
var ErrVersionMismatch = errors.New("kryptograf/chunkio: unsupported frame version")

// ErrCounterMismatch indicates out-of-order or duplicated frames.
var ErrCounterMismatch = errors.New("kryptograf/chunkio: frame counter mismatch")

// EncodeHeader serialises the header into buf. buf must be at least
// FrameHeaderSize bytes long.
func EncodeHeader(buf []byte, h Header) {
	if len(buf) < FrameHeaderSize {
		panic("kryptograf/chunkio: header buffer too small")
	}
	buf[0] = h.Version
	buf[1] = h.Flags
	binary.BigEndian.PutUint32(buf[2:6], h.Counter)
	binary.BigEndian.PutUint32(buf[6:10], h.Payload)
}

// DecodeHeader parses buf into a Header. The payload length is returned in
// bytes.
func DecodeHeader(buf []byte) (Header, error) {
	if len(buf) < FrameHeaderSize {
		return Header{}, fmt.Errorf("decode header: need %d bytes, got %d", FrameHeaderSize, len(buf))
	}
	h := Header{
		Version: buf[0],
		Flags:   buf[1],
		Counter: binary.BigEndian.Uint32(buf[2:6]),
		Payload: binary.BigEndian.Uint32(buf[6:10]),
	}
	if h.Version != frameVersion1 {
		return Header{}, ErrVersionMismatch
	}
	return h, nil
}

// NextCounter validates and increments the counter, returning an error if the
// counter space is exhausted.
func NextCounter(current uint32) (uint32, error) {
	if current == maxFrameCounter {
		return 0, fmt.Errorf("kryptograf/chunkio: frame counter exhausted")
	}
	return current + 1, nil
}

// FinalFlag reports whether the header marks the final frame in the stream.
func FinalFlag(h Header) bool {
	return h.Flags&flagFinalFrame == flagFinalFrame
}

// MarkFinal toggles the final-frame flag on the header.
func MarkFinal(h *Header) {
	h.Flags |= flagFinalFrame
}

// FrameVersion returns the currently supported frame version.
func FrameVersion() uint8 {
	return frameVersion1
}
