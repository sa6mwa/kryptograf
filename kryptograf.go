// kryptograf is a Go package for exchanging AES-128/224/256-CFB
// encrypted HMAC-SHA256 signed data or messages as either byte
// slices, base64 raw standard encoded strings or json streams.
//
// Usage example:
//
//	k := kryptograf.NewKryptograf()
//	ciphertextString, err := k.EncryptToString([]byte("Hello world"))
//	if err != nil {
//		panic(err)
//	}
//	plaintext, err := k.DecryptString(ciphertextString)
//	if err != nil {
//		panic(err)
//	}
//	fmt.Println(string(plaintext))
//
//	newKey := kryptograf.NewKey()
//	if _, err := k.SetEncryptionKey(newKey); err != nil {
//		panic(err)
//	}
//	ciphertextString, err := k.EncryptToString([]byte("Once upon a time..."))
//	if err != nil {
//		panic(err)
//	}
//	plaintext, err := k.DecryptString(ciphertextString)
//	if err != nil {
//		panic(err)
//	}
//	fmt.Println(string(plaintext))
//
// You can generate a new base64 encoded key for use with
// SetEncryptionKey using the newkey command:
//
//	go run github.com/sa6mwa/kryptograf/cmd/newkey@latest
//
// kryptograf Copyright (c) 2023 Michel Blomgren sa6mwa@gmail.com
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package kryptograf

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	DefaultEncryptionKey string = "TfLe2CpLn6qs8t6eQmGJnFGkU8NskfcC9AWOSEFlnLY"
)

var (
	GzipByDefault bool = false
)

var (
	ErrKeyLength            error = errors.New("key length must be 16, 24 or 32 (for AES-128, AES-192 or AES-256)")
	ErrHMACValidationFailed error = errors.New("HMAC validation failed (corrupt data or wrong encryption key)")
)

type Kryptograf interface {
	// GetEncryptionKey returns the instance's encryption key as a byte slice.
	GetEncryptionKey() []byte

	// SetEncryptionKey sets the instance encryption key from a base64
	// raw standard encoded string.
	SetEncryptionKey(key string) (Kryptograf, error)

	// EnableGzip will gzip the message before Encrypt or gunzip the
	// plaintext after Decrypt of ciphertext.
	EnableGzip() Kryptograf

	// DisableGzip will turn off gzipping messages before Encrypt or
	// gunzipping the plaintext after Decrypt of ciphertext.
	DisableGzip() Kryptograf

	// Returns true if the instance will gzip plaintext messages before
	// Encrypt or gunzip ciphertext after Decrypt, false if not.
	Gzip() bool

	// Encrypt enciphers (the optionally gzipped) data byte slice using
	// the instance key and returns a byte slice with encrypted data in
	// the format of the Encrypt function or error in case of
	// failure. The returned byte slice can be decrypted using
	// Kryptograf_Decrypt given matching key and value of gzip boolean.
	Encrypt(data []byte) ([]byte, error)

	// Decrypt deciphers (the optionally gzipped) data byte slice using
	// the instance key and returns a byte slice with the plaintext
	// (decrypted) data or error in case of failure. The format of the
	// ciphertext data slice is documented in the Encrypt function.
	Decrypt(data []byte) ([]byte, error)

	// Recv reads binary ciphertext from r and returns the plaintext as
	// a byte slice or error on failure.
	Recv(r io.Reader) ([]byte, error)

	// Send sends plaintext as ciphertext to io.Writer w. Returns error
	// if encryption or w.Write fails.
	Send(plaintext []byte, w io.Writer) error

	// EncryptToString encrypts data and returns the output of
	// base64.RawStdEncoding.EncodeToString or error in case encryption
	// failed.
	EncryptToString(data []byte) (string, error)

	// DecryptString passes base64RawStdEncodedData through
	// base64.RawStdEncoding.DecodeString and returns the plaintext as a
	// byte slice or error if either decryption or base64 decoding
	// failed.
	DecryptString(base64RawStdEncodedData string) ([]byte, error)

	// RecvFromJson executes at least one json.Decode on j returning
	// exactly one successfully decrypted json key/value pair as a
	// map[string][]byte or error per call. RecvFromJson uses
	// json.Decode underneath and can be repeatedly called on j until
	// returning error io.EOF indicating there is no more data to read
	// from the stream. If you require that every incoming json object
	// is successfully decrypted you can set the optional variadic
	// boolean to true, in which case RecvFromJson will return error if
	// any incoming json object fail decryption. Format of the incoming
	// json stream is:
	//
	//	{"msg1":"base64EncodedCipherText"}
	//	{"msg2":"base64EncodedCipherText"}
	//	...etc.
	//
	// RecvFromJson will decrypt json generated with
	// Kryptograf_EncryptToJson.
	//
	// Example:
	//	jsonText := `{"msgkey_eg_timestamp":"base64ciphertext"}`
	//	plaintexts, err := k.RecvFromJson(json.NewDecoder(strings.NewReader(jsonText)))
	//	if err == io.EOF {
	//		// break
	//	} else if err != nil {
	//		// panic(err)
	//	}
	//	for k, v := range plaintexts {
	//		fmt.Printf("%s: %v\n", k, v)
	//	}
	RecvFromJson(j *json.Decoder, allMustDecrypt ...bool) (map[string][]byte, error)

	// EncryptToJson sends the plaintext value as ciphertext value per
	// each key in messages via json.Encode to w. If any of the values
	// in messages fail to be encrypted the function will return an
	// error.
	EncryptToJson(messages map[string][]byte, w io.Writer) error
}

type kryptograf struct {
	key  []byte
	gzip bool
}

// NewKryptograf returns a new kryptograf instance with the default
// encryption key and gzip disabled by default (the value of
// kryptograf.GzipByDefault). Use the method SetEncryptionKey to set
// your own encryption key (from a base64 raw standard encoded
// string).
func NewKryptograf() Kryptograf {
	binkey, err := base64.RawStdEncoding.DecodeString(DefaultEncryptionKey)
	if err != nil {
		panic(err)
	}
	return &kryptograf{
		key:  binkey,
		gzip: GzipByDefault,
	}
}

func (k *kryptograf) GetEncryptionKey() []byte {
	return k.key
}

func (k *kryptograf) SetEncryptionKey(key string) (Kryptograf, error) {
	binkey, err := base64.RawStdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	switch len(binkey) {
	case 16, 24, 32:
	default:
		return k, ErrKeyLength
	}
	k.key = binkey
	return k, nil
}

func (k *kryptograf) EnableGzip() Kryptograf {
	k.gzip = true
	return k
}

func (k *kryptograf) DisableGzip() Kryptograf {
	k.gzip = false
	return k
}

func (k *kryptograf) Gzip() bool {
	return k.gzip
}

func (k *kryptograf) Encrypt(data []byte) ([]byte, error) {
	var plaintext []byte
	if len(data) == 0 {
		return nil, errors.New("nothing to encrypt")
	}
	if k.gzip {
		var output bytes.Buffer
		gz := gzip.NewWriter(&output)
		if _, err := gz.Write(data); err != nil {
			return nil, err
		}
		if err := gz.Close(); err != nil {
			return nil, err
		}
		plaintext = output.Bytes()
	} else {
		plaintext = data
	}
	return Encrypt(k.key, plaintext)
}

func (k *kryptograf) Decrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("nothing to decrypt")
	}
	decrypted, err := Decrypt(k.key, data)
	if err != nil {
		return nil, err
	}
	if k.gzip {
		var output bytes.Buffer
		gz, err := gzip.NewReader(bytes.NewReader(decrypted))
		if err != nil {
			return nil, err
		}
		if _, err := output.ReadFrom(gz); err != nil {
			return nil, err
		}
		decrypted = output.Bytes()
	}
	return decrypted, nil
}

func (k *kryptograf) Recv(r io.Reader) ([]byte, error) {
	var input bytes.Buffer
	if _, err := input.ReadFrom(r); err != nil {
		return nil, err
	}
	return k.Decrypt(input.Bytes())
}

func (k *kryptograf) Send(plaintext []byte, w io.Writer) error {
	ciphertext, err := k.Encrypt(plaintext)
	if err != nil {
		return err
	}
	if _, err := w.Write(ciphertext); err != nil {
		return err
	}
	return nil
}

func (k *kryptograf) EncryptToString(data []byte) (string, error) {
	ciphertext, err := k.Encrypt(data)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

func (k *kryptograf) DecryptString(base64RawStdEncodedData string) ([]byte, error) {
	plaintext, err := base64.RawStdEncoding.DecodeString(base64RawStdEncodedData)
	if err != nil {
		return nil, err
	}
	return k.Decrypt(plaintext)
}

func (k *kryptograf) RecvFromJson(j *json.Decoder, allMustDecrypt ...bool) (map[string][]byte, error) {
	var kv map[string][]byte
	output := make(map[string][]byte)
	for {
		if err := j.Decode(&kv); err != nil {
			return nil, err
		}
		for key, value := range kv {
			plaintext, err := k.Decrypt(value)
			if err != nil {
				if len(allMustDecrypt) > 0 && allMustDecrypt[0] {
					return nil, err
				}
			} else {
				output[key] = plaintext
			}
		}
		if len(output) > 0 {
			break
		}
	}
	return output, nil
}

func (k *kryptograf) EncryptToJson(messages map[string][]byte, w io.Writer) error {
	jsonEncoder := json.NewEncoder(w)
	for key, plaintext := range messages {
		kv := make(map[string][]byte)
		ciphertext, err := k.Encrypt(plaintext)
		if err != nil {
			return err
		}
		kv[key] = ciphertext
		if err := jsonEncoder.Encode(&kv); err != nil {
			return err
		}
	}
	return nil
}

// NewKey generates a 32 byte base64 encoded random string for use as
// an AES-256 key. Get a new key from the command line:
//
//	go run github.com/sa6mwa/kryptograf/cmd/newkey@latest
func NewKey() string {
	randomBytes := make([]byte, 32)
	retries := 50
	for i := 0; i < retries; i++ {
		if _, err := rand.Read(randomBytes); err != nil {
			continue
		}
		break
	}
	return base64.RawStdEncoding.EncodeToString(randomBytes)
}

// Encrypt encrypts data using a 16, 24 or 32 byte long key (for
// AES-128-CFB, AES-224-CFB or AES-256-CFB). The cipher-data is
// prepended with a HMAC-SHA256 hash (32 bytes) and IV (or salt if you
// prefer). Same key is used for HMAC and. The format of the output
// data slice is:
//
//	b = bytes
//	[HMAC_of_IV_and_cipherdata_32_b][IV_16_b][cipherdata]
func Encrypt(key []byte, data []byte) ([]byte, error) {
	// Maybe implement later, but comes from an external package...
	//dk := pbkdf2.Key(key, []byte(salt), 4096, 32, sha256.New)

	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, ErrKeyLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, key)

	ciphered := make([]byte, mac.Size()+aes.BlockSize+len(data))
	iv := ciphered[mac.Size() : aes.BlockSize+mac.Size()]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphered[mac.Size()+aes.BlockSize:], data)

	if _, err := mac.Write(ciphered[mac.Size():]); err != nil {
		return nil, err
	}
	copy(ciphered[:mac.Size()], mac.Sum(nil))
	return ciphered, nil
}

// Decrypt authenticates and decrypts data using a 16, 24 or 32 byte
// long key (for AES-128-CFB, AES-224-CFB or AES-256-CFB). The data
// should start with a HMAC-SHA256 hash (32 bytes) initialized with
// key. The hash function should hash the rest of data which includes
// an aes.BlockSize long IV and the AES-CFB encrypted data. Returns
// clear-data or error in case of failure. Returns
// anystore.ErrHMACValidationFailed when the key is wrong or the
// message is corrupt or tampered with.
func Decrypt(key []byte, data []byte) ([]byte, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, ErrKeyLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, key)

	if len(data) < mac.Size()+aes.BlockSize {
		return nil, fmt.Errorf("data shorter than HMAC + AES block size (%d)", mac.Size()+aes.BlockSize)
	}

	messageMAC := data[:mac.Size()]
	if _, err := mac.Write(data[mac.Size():]); err != nil {
		return nil, err
	}
	if !hmac.Equal(messageMAC, mac.Sum(nil)) {
		return nil, ErrHMACValidationFailed
	}
	iv := data[mac.Size() : mac.Size()+aes.BlockSize]
	deciphered := make([]byte, len(data[mac.Size()+aes.BlockSize:]))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(deciphered, data[mac.Size()+aes.BlockSize:])
	return deciphered, nil
}

func ToBinaryEncryptionKey(base64RawStdEncoding string) ([]byte, error) {
	binkey, err := base64.RawStdEncoding.DecodeString(base64RawStdEncoding)
	if err != nil {
		return nil, err
	}
	return binkey, nil
}
