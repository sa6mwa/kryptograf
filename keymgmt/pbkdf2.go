package keymgmt

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

// PBKDF2Params describes the hash function and iteration count used to derive
// a root key from a passphrase.
type PBKDF2Params struct {
	Hash       func() hash.Hash
	Iterations int
	Salt       []byte
	KeyLength  int
}

const (
	defaultPBKDF2Iterations = 600_000
	defaultPBKDF2KeyBytes   = rootKeyBytes
	defaultPBKDF2SaltBytes  = 32
)

// ErrInvalidPBKDF2Params indicates bad configuration values.
var ErrInvalidPBKDF2Params = errors.New("kryptograf/keymgmt: invalid PBKDF2 parameters")

// ErrUnsupportedPBKDF2Hash indicates the hash function cannot be serialised.
var ErrUnsupportedPBKDF2Hash = errors.New("kryptograf/keymgmt: unsupported PBKDF2 hash")

// GeneratePBKDF2Params produces a PBKDF2Params struct populated with secure
// defaults: SHA-256, 600k iterations, a fresh 32-byte salt, and a 32-byte key.
func GeneratePBKDF2Params() (PBKDF2Params, error) {
	salt, err := GenerateSalt(defaultPBKDF2SaltBytes)
	if err != nil {
		return PBKDF2Params{}, err
	}
	return PBKDF2Params{
		Hash:       sha256.New,
		Iterations: defaultPBKDF2Iterations,
		Salt:       salt,
		KeyLength:  defaultPBKDF2KeyBytes,
	}, nil
}

// MustGeneratePBKDF2Params is the panic-on-error variant of GeneratePBKDF2Params.
func MustGeneratePBKDF2Params() PBKDF2Params {
	params, err := GeneratePBKDF2Params()
	if err != nil {
		panic(err)
	}
	return params
}

// DeriveKeyFromPassphrase produces a RootKey using PBKDF2, applying secure
// defaults when params is omitted. The resulting parameters are returned so
// callers can persist them alongside the derived key.
func DeriveKeyFromPassphrase(passphrase []byte, params ...PBKDF2Params) (RootKey, PBKDF2Params, error) {
	var cfg PBKDF2Params
	if len(params) > 0 {
		cfg = params[0]
	}
	if err := normalizePBKDF2Params(&cfg); err != nil {
		return RootKey{}, PBKDF2Params{}, err
	}

	key := pbkdf2.Key(passphrase, cfg.Salt, cfg.Iterations, cfg.KeyLength, cfg.Hash)
	root, err := RootKeyFromBytes(key)
	if err != nil {
		return RootKey{}, PBKDF2Params{}, err
	}
	return root, cfg, nil
}

type pbkdf2Record struct {
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
	Salt       []byte `json:"salt"`
	KeyLength  int    `json:"key_length"`
}

// MarshalPBKDF2Params serialises PBKDF2 parameters for persistence.
func MarshalPBKDF2Params(params PBKDF2Params) ([]byte, error) {
	id, err := hashIdentifier(params.Hash)
	if err != nil {
		return nil, err
	}
	record := pbkdf2Record{
		Hash:       id,
		Iterations: params.Iterations,
		Salt:       slices.Clone(params.Salt),
		KeyLength:  params.KeyLength,
	}
	return json.Marshal(record)
}

// UnmarshalPBKDF2Params deserialises PBKDF2 parameters created with MarshalPBKDF2Params.
func UnmarshalPBKDF2Params(data []byte) (PBKDF2Params, error) {
	var record pbkdf2Record
	if err := json.Unmarshal(data, &record); err != nil {
		return PBKDF2Params{}, fmt.Errorf("unmarshal PBKDF2 params: %w", err)
	}
	params := PBKDF2Params{
		Hash:       hashFromIdentifier(record.Hash),
		Iterations: record.Iterations,
		Salt:       slices.Clone(record.Salt),
		KeyLength:  record.KeyLength,
	}
	if params.Hash == nil {
		return PBKDF2Params{}, fmt.Errorf("%w: %q", ErrUnsupportedPBKDF2Hash, record.Hash)
	}
	if err := normalizePBKDF2Params(&params); err != nil {
		return PBKDF2Params{}, err
	}
	return params, nil
}

func hashIdentifier(fn func() hash.Hash) (string, error) {
	if fn == nil || sameHash(fn, sha256.New) {
		return "sha256", nil
	}
	return "", ErrUnsupportedPBKDF2Hash
}

func hashFromIdentifier(id string) func() hash.Hash {
	switch id {
	case "", "sha256":
		return sha256.New
	default:
		return nil
	}
}

func sameHash(a, b func() hash.Hash) bool {
	if a == nil || b == nil {
		return false
	}
	return fmt.Sprintf("%T", a()) == fmt.Sprintf("%T", b())
}

func normalizePBKDF2Params(cfg *PBKDF2Params) error {
	if cfg.Iterations <= 0 {
		cfg.Iterations = defaultPBKDF2Iterations
	}
	if cfg.Hash == nil {
		cfg.Hash = sha256.New
	}
	if cfg.KeyLength <= 0 {
		cfg.KeyLength = defaultPBKDF2KeyBytes
	}
	if cfg.KeyLength != rootKeyBytes {
		return fmt.Errorf("%w: expected %d-byte key, got %d", ErrInvalidPBKDF2Params, rootKeyBytes, cfg.KeyLength)
	}
	if len(cfg.Salt) == 0 {
		salt, err := GenerateSalt(defaultPBKDF2SaltBytes)
		if err != nil {
			return err
		}
		cfg.Salt = salt
	} else {
		cfg.Salt = slices.Clone(cfg.Salt)
	}
	return nil
}

func equalPBKDF2Params(a, b PBKDF2Params) bool {
	idA, errA := hashIdentifier(a.Hash)
	idB, errB := hashIdentifier(b.Hash)
	if errA != nil || errB != nil {
		return false
	}
	return idA == idB && a.Iterations == b.Iterations && a.KeyLength == b.KeyLength && slices.Equal(a.Salt, b.Salt)
}

// GenerateSalt returns n bytes of cryptographically secure random data.
func GenerateSalt(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("generate salt: length must be > 0")
	}
	salt := make([]byte, n)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// PromptPassphrase reads a passphrase from r without echoing when r is a TTY.
// The prompt is written to w if provided. If r is nil, os.Stdin is used.
func PromptPassphrase(r io.Reader, prompt string, w io.Writer) ([]byte, error) {
	if r == nil {
		r = os.Stdin
	}
	if fd := fileDescriptor(r); fd >= 0 && term.IsTerminal(fd) {
		if w != nil && prompt != "" {
			if _, err := io.WriteString(w, prompt); err != nil {
				return nil, fmt.Errorf("write prompt: %w", err)
			}
		}
		state, err := term.GetState(fd)
		if err != nil {
			passphrase, err := term.ReadPassword(fd)
			if err != nil {
				return nil, fmt.Errorf("read passphrase: %w", err)
			}
			if w != nil {
				if _, err := io.WriteString(w, "\n"); err != nil {
					return nil, fmt.Errorf("write newline: %w", err)
				}
			}
			return passphrase, nil
		}

		signals := terminalSignals()
		var (
			sigCh  chan os.Signal
			doneCh chan struct{}
			once   sync.Once
		)
		restore := func() {
			once.Do(func() {
				_ = term.Restore(fd, state)
			})
		}
		if len(signals) > 0 {
			sigCh = make(chan os.Signal, 1)
			doneCh = make(chan struct{})
			signal.Notify(sigCh, signals...)
			go func() {
				select {
				case <-doneCh:
					return
				case sig := <-sigCh:
					restore()
					os.Exit(exitCodeForSignal(sig))
				}
			}()
			defer func() {
				close(doneCh)
				if sigCh != nil {
					signal.Stop(sigCh)
				}
			}()
		}
		defer restore()

		passphrase, err := term.ReadPassword(fd)
		if err != nil {
			return nil, fmt.Errorf("read passphrase: %w", err)
		}
		if w != nil {
			if _, err := io.WriteString(w, "\n"); err != nil {
				return nil, fmt.Errorf("write newline: %w", err)
			}
		}
		return passphrase, nil
	}
	return promptPassphraseFromReader(r, prompt, w)
}

// PromptAndDeriveRootKey prompts the user for a passphrase using reader r,
// derives a RootKey with optional PBKDF2 parameters, and returns both the key
// and the parameters actually used. Supplying no params applies the secure
// defaults (SHA-256, 600k iterations, 32-byte salt, 32-byte key). If r is nil,
// os.Stdin is used. When r is attached to a terminal, the input is read
// without echo; otherwise a newline-terminated passphrase is consumed.
func PromptAndDeriveRootKey(r io.Reader, prompt string, w io.Writer, params ...PBKDF2Params) (RootKey, PBKDF2Params, error) {
	if r == nil {
		r = os.Stdin
	}
	var passphrase []byte
	var err error
	passphrase, err = PromptPassphrase(r, prompt, w)
	if err != nil {
		return RootKey{}, PBKDF2Params{}, err
	}
	defer zeroBytes(passphrase)

	key, paramsUsed, err := DeriveKeyFromPassphrase(passphrase, params...)
	if err != nil {
		return RootKey{}, PBKDF2Params{}, err
	}
	return key, paramsUsed, nil
}

func promptPassphraseFromReader(r io.Reader, prompt string, w io.Writer) ([]byte, error) {
	if w != nil && prompt != "" {
		if _, err := io.WriteString(w, prompt); err != nil {
			return nil, fmt.Errorf("write prompt: %w", err)
		}
	}
	reader := bufio.NewReader(r)
	line, err := reader.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	passphrase := slices.Clone(bytes.TrimRight(line, "\r\n"))
	if w != nil {
		if _, err := io.WriteString(w, "\n"); err != nil {
			return nil, fmt.Errorf("write newline: %w", err)
		}
	}
	return passphrase, nil
}

func fileDescriptor(r io.Reader) int {
	type fder interface {
		Fd() uintptr
	}
	if f, ok := r.(fder); ok {
		return int(f.Fd())
	}
	return -1
}

func exitCodeForSignal(sig os.Signal) int {
	if sig == nil {
		return 1
	}
	if s, ok := sig.(syscall.Signal); ok {
		return 128 + int(s)
	}
	if sig == os.Interrupt {
		return 130
	}
	return 1
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
