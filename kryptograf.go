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
// This documentation was generated with the following command:
//
//	go run github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest > README.md
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
	"context"
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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sa6mwa/kryptograf/internal/pkg/crand"
	"github.com/sa6mwa/kryptograf/internal/pkg/tokenauth"
)

const (
	DefaultEncryptionKey     string = "TfLe2CpLn6qs8t6eQmGJnFGkU8NskfcC9AWOSEFlnLY"
	DefaultPersisterEndpoint string = "http://localhost:11185"
)

var (
	GzipByDefault bool = false
)

var (
	ErrKeyLength            error = errors.New("key length must be 16, 24 or 32 (for AES-128, AES-192 or AES-256)")
	ErrHMACValidationFailed error = errors.New("HMAC validation failed (corrupt data or wrong encryption key)")
	ErrStop                 error = errors.New("stopped processing json stream")
	ErrKeyExists            error = errors.New("key already exist in KeyValueMap")
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
	// map[string][]byte (kryptograf.KeyValueMap) or error per
	// call. RecvFromJson uses json.Decode underneath and can be
	// repeatedly called on j until returning error io.EOF indicating
	// there is no more data to read from the stream. RecvFromJson uses
	// KeyValueMap_PutSequential to handle any duplicates returned since
	// keys need to be unique. If you require that every incoming json
	// object is successfully decrypted you can set the optional
	// variadic boolean to true, in which case RecvFromJson will return
	// error if any incoming json object fail decryption. Format of the
	// incoming json stream is:
	//
	//	{"msg1":"base64EncodedCipherText"}
	//	{"msg2":"base64EncodedCipherText"}
	//	...etc.
	//
	// RecvFromJson will decrypt json generated with
	// Kryptograf_EncryptToJson.
	//
	// Example:
	//
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
	RecvFromJson(j *json.Decoder, allMustDecrypt ...bool) (KeyValueMap, error)

	// EncryptToJson sends the plaintext value as ciphertext value per
	// each key in messages via json.Encode to w. If any of the values
	// in messages fail to be encrypted the function will return an
	// error.
	EncryptToJson(messages KeyValueMap, w io.Writer) error

	// RecvFunc uses json.NewDecoder(jsonStream).Decode to read one or
	// more {"key":"ciphertext"} into a KeyValueMap (map[string][]byte)
	// from jsonStream. Key and decrypted ciphertext is passed as key
	// and plaintext to function f. If json Decode or kryptograf Decrypt
	// returns an error it is passed as err to function f in which case
	// key and plaintext will likely be empty and nil respectively. If
	// function f returns kryptograf.ErrStop it is treated as a break
	// and RecvFunc will return with a nil error. Any other error
	// returned by function f will cause RecvFunc to return immediately
	// with that error while nil errors will continue the receive loop
	// (until jsonStream is closed or an error occurs).
	RecvFunc(jsonStream io.Reader, f func(key string, plaintext []byte, err error) error) error

	// SendFunc uses json.NewEncoder(jsonStream).Encode to write
	// {"key":"ciphertext"} objects to jsonStream compatible with the
	// json encrypt functions provided by Kryptograf (e.g RecvFromJson,
	// RecvFromJsonStream or RecvFunc). Function f is repeatedly called
	// and expected to return a key (for example timestamp, message
	// type, name, etc), plaintext as a byte slice and error code. If
	// the error returned from f is kryptograf.ErrStop it is treated as
	// a break and SendFunc returns a nil error. Any other error
	// returned by f causes SendFunc to return with that error
	// immediately. Plaintext is passed through Encrypt, json encoded
	// into into {"key":"ciphertext"} and written to the
	// jsonStream. Please note, if plaintext is nil, no json message is
	// sent. If there are no errors, function f is repeatedly called and
	// every returned plaintext results in a {"key":"ciphertext"} object
	// written to jsonStream.
	SendFunc(jsonStream io.Writer, f func() (key string, plaintext []byte, err error)) error
}

type kryptograf struct {
	key  []byte
	gzip bool
}

type KeyValueMap map[string][]byte

func (m KeyValueMap) Get(key string) []byte {
	return m[key]
}

// Put stores data under key in KeyValueMap. If key already exist, Put
// returns kryptograf.ErrKeyExists.
func (m KeyValueMap) Put(key string, data []byte) error {
	if _, exists := m[key]; exists {
		return ErrKeyExists
	}
	m[key] = data
	return nil
}

// PutSequential will append _{int} to key (e.g key_1) if key already
// exist in the KeyValueMap. If key_2 exists, it will try key_3,
// etc. Method returns the key used to store data (key or key_1,
// key_2, etc). PutSequential is not go routine safe, use sync/atomic
// for that.
func (m KeyValueMap) PutSequential(key string, data []byte) string {
	seq := 1
	newKey := key
	for {
		if _, exists := m[newKey]; exists {
			newKey = key + "_" + strconv.Itoa(seq)
			seq++
			continue
		}
		break
	}
	m[newKey] = data
	return newKey
}

// Deletes key from KeyValueMap.
func (m KeyValueMap) Delete(key string) {
	delete(m, key)
}

// Returns the length of the KeyValueMap (number of keys).
func (m KeyValueMap) Len() int {
	return len(m)
}

// ForEach calls function f for each key-value pair in the
// KeyValueMap. If function f returns kryptograf.ErrStop it is treated
// as a break from the loop and ForEach will return a nil error. Any
// other error returned from f is passed as the output error of
// ForEach.
func (m KeyValueMap) ForEach(f func(key string, data []byte) error) error {
	for k, v := range m {
		if err := f(k, v); err == ErrStop {
			return nil
		} else if err != nil {
			return err
		}
	}
	return nil
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

func (k *kryptograf) RecvFromJson(j *json.Decoder, allMustDecrypt ...bool) (KeyValueMap, error) {
	output := make(KeyValueMap)
	for {
		var kv KeyValueMap
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
				output.PutSequential(key, plaintext)
			}
		}
		if len(output) > 0 {
			break
		}
	}
	return output, nil
}

func (k *kryptograf) EncryptToJson(messages KeyValueMap, w io.Writer) error {
	jsonEncoder := json.NewEncoder(w)
	for key, plaintext := range messages {
		kv := make(KeyValueMap)
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

func (k *kryptograf) RecvFunc(jsonStream io.Reader, f func(key string, plaintext []byte, err error) error) error {
	j := json.NewDecoder(jsonStream)
	for {
		var kv KeyValueMap
		if err := j.Decode(&kv); err == nil {
			for key, value := range kv {
				plaintext, e := k.Decrypt(value)
				if err := f(key, plaintext, e); err != nil {
					if err == ErrStop {
						return nil
					}
					return err
				}
			}
		} else {
			if err := f("", nil, err); err != nil {
				if err == ErrStop {
					return nil
				}
				return err
			}
		}
	}
}

func (k *kryptograf) SendFunc(jsonStream io.Writer, f func() (key string, plaintext []byte, err error)) error {
	j := json.NewEncoder(jsonStream)
	for {
		key, plaintext, err := f()
		if err != nil {
			if err == ErrStop {
				return nil
			}
			return err
		}
		if plaintext != nil {
			kv := make(KeyValueMap)
			ciphertext, err := k.Encrypt(plaintext)
			if err != nil {
				return err
			}
			kv[key] = ciphertext
			if err := j.Encode(&kv); err != nil {
				return err
			}
		}
	}
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

// ToBinaryEncryptionKey takes a base64 raw standard encoded string
// and decodes it into a byte slice.
func ToBinaryEncryptionKey(base64RawStdEncoding string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(base64RawStdEncoding)
}

// RandomStamp returns time.Now().UTC() as time.Format
// "20060102T150405.999999999_{19 character random int63}". If one tm
// is provided in the optional variadic argument, the first time.Time
// from the tm slice is used instead of time.Now().UTC(). Intended
// usage of this function is for creating keys for a KV
// map[string][]byte pair (KeyValueMap) sent as a json stream.
func RandomStamp(tm ...time.Time) string {
	format := "20060102T150405.999999999"
	t := time.Now().UTC()
	if len(tm) > 0 {
		t = tm[0]
	}
	return t.Format(format) + fmt.Sprintf("_%.19d", crand.Int63())
}

// Persistence API client toward server
// github.com/sa6mwa/kryptografpersister.
type Persistence struct {
	// endpoint to kryptografpersister (defaults to http://localhost:11185)
	endpoint string
	token    string
	key      []byte
	k        Kryptograf
	u        *url.URL
	c        *http.Client
}

// Returns a new kryptograf.Persistence API client. Persistence is
// used to send a kryptograf json stream to
// github.com/sa6mwa/kryptografpersister. The persister is a HTTP API
// that consume ciphertext from a KeyValueMap (map[string][]byte) json
// stream (e.g EncryptToJson or SendFunc) and store in an
// AnystoreDB. The server (persister) does not know of the client's
// key and can therefore not decrypt or validate the ciphertext. Keys
// can be retrieved from the server via GET requests and will be
// seamlessly decrypted using this Persistence client.
//
//	newKey := kryptograf.NewKey()
//	k, err := kryptograf.NewKryptograf().EnableGzip().SetEncryptionKey(newKey)
//	if err != nil {
//		panic(err)
//	}
//	// Assume kryptografpersister is running on http://localhost:11185
//	pc, err := kryptograf.NewPersistenceClient("", newKey, k)
//	if err != nil {
//		panic(err)
//	}
//	if err := pc.Store(context.Background(), "myThing", []byte("Hello world")); err != nil {
//		panic(err)
//	}
func NewPersistenceClient(persisterURL, bearerToken string, k Kryptograf) (*Persistence, error) {
	p := &Persistence{
		endpoint: strings.TrimSpace(persisterURL),
		token:    strings.TrimSpace(bearerToken),
		k:        k,
	}
	if p.endpoint == "" {
		p.endpoint = DefaultPersisterEndpoint
	}
	if u, err := url.Parse(p.endpoint); err != nil {
		return nil, err
	} else {
		p.u = u
	}
	p.c = &http.Client{
		Transport: http.DefaultTransport,
		Timeout:   30 * time.Second,
	}
	if p.token != "" {
		p.c.Transport = &tokenauth.Injector{Token: p.token, OriginalTransport: p.c.Transport}
	}
	return p, nil
}

// SetHTTPClient can be used to replace the default http.Client used
// by the Persistence client.
func (p *Persistence) SetHTTPClient(client *http.Client) *Persistence {
	p.c = client
	return p
}

// SetHTTPTransport replaces the http.Client Transport.
func (p *Persistence) SetHTTPTransport(transport *http.Transport) *Persistence {
	if p.c != nil {
		p.c.Transport = transport
	}
	return p
}

// Store persists a single key-value pair in the persister.
func (p *Persistence) Store(ctx context.Context, key string, plaintext []byte) error {
	if key == "" {
		key = RandomStamp()
	}
	r, w := io.Pipe()
	returnCh := make(chan error)
	go func() {
		kv := make(KeyValueMap)
		kv[key] = plaintext
		if err := p.k.EncryptToJson(kv, w); err != nil {
			returnCh <- err
		}
		w.Close()
		close(returnCh)
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.u.String(), r)
	if err != nil {
		return err
	}
	resp, err := p.c.Do(req)
	goferr := <-returnCh
	if goferr != nil && err != nil {
		return fmt.Errorf("%w: %w", err, goferr)
	} else if err != nil {
		return err
	} else if goferr != nil {
		resp.Body.Close()
		return goferr
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	default:
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			return fmt.Errorf("got %d %s from server: %v", resp.StatusCode, http.StatusText(resp.StatusCode), body)
		}
		return fmt.Errorf("got %d %s from server, unable to read body: %w", resp.StatusCode, http.StatusText(resp.StatusCode), err)
	}
}

// StoreFunc persists one or multiple key-value pairs in the
// persister. Request is ended when function f returns
// kryptograf.ErrStop or other error (uses SendFunc underneath). If
// function f returns a nil error it sends the key and plaintext, any
// error including ErrStop discards any key and plaintext return
// values.
func (p *Persistence) StoreFunc(ctx context.Context, f func() (key string, plaintext []byte, err error)) error {
	r, w := io.Pipe()
	returnCh := make(chan error)
	go func() {
		if err := p.k.SendFunc(w, f); err != nil {
			returnCh <- err
		}
		w.Close()
		close(returnCh)
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.u.String(), r)
	if err != nil {
		return err
	}
	resp, err := p.c.Do(req)
	goferr := <-returnCh
	if goferr != nil && err != nil {
		return fmt.Errorf("%w: %w", err, goferr)
	} else if err != nil {
		return err
	} else if goferr != nil {
		resp.Body.Close()
		return goferr
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	default:
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			return fmt.Errorf("got %d %s from server: %v", resp.StatusCode, http.StatusText(resp.StatusCode), body)
		}
		return fmt.Errorf("got %d %s from server, unable to read body: %w", resp.StatusCode, http.StatusText(resp.StatusCode), err)
	}
}

// Not implemented yet!
// func (p *Persistence) Load(ctx context.Context, key string) ([]byte, error) {
// 	return nil, nil
// }

// LoadAll creates a new http request with ctx and calls function f
// for every decrypted key-value pair returned by the server. The
// logic of function f is the same as RecvFunc, refer to the RecvFunc
// documentation for further information.
func (p *Persistence) LoadAll(ctx context.Context, f func(key string, plaintext []byte, err error) error) error {
	r, w := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.u.String(), nil)
	if err != nil {
		return err
	}
	returnCh := make(chan error)
	go func() {
		defer close(returnCh)
		resp, err := p.c.Do(req)
		if err != nil {
			returnCh <- err
			w.Close()
			return
		}
		defer resp.Body.Close()
		if _, err := io.Copy(w, resp.Body); err != nil {
			returnCh <- err
		}
		w.Close()
	}()
	if err := p.k.RecvFunc(r, f); err != nil {
		return err
	}
	return nil
}
