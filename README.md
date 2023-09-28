<!-- Code generated by gomarkdoc. DO NOT EDIT -->

# kryptograf

```go
import "github.com/sa6mwa/kryptograf"
```

kryptograf is a Go package for exchanging AES\-128/224/256\-CFB encrypted HMAC\-SHA256 signed data or messages as either byte slices, base64 raw standard encoded strings or json streams.

Usage example:

```
k := kryptograf.NewKryptograf()
ciphertextString, err := k.EncryptToString([]byte("Hello world"))
if err != nil {
	panic(err)
}
plaintext, err := k.DecryptString(ciphertextString)
if err != nil {
	panic(err)
}
fmt.Println(string(plaintext))

newKey := kryptograf.NewKey()
if _, err := k.SetEncryptionKey(newKey); err != nil {
	panic(err)
}
ciphertextString, err := k.EncryptToString([]byte("Once upon a time..."))
if err != nil {
	panic(err)
}
plaintext, err := k.DecryptString(ciphertextString)
if err != nil {
	panic(err)
}
fmt.Println(string(plaintext))
```

You can generate a new base64 encoded key for use with SetEncryptionKey using the newkey command:

```
go run github.com/sa6mwa/kryptograf/cmd/newkey@latest
```

This documentation was generated with the following command:

```
go run github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest > README.md
```

kryptograf Copyright \(c\) 2023 Michel Blomgren sa6mwa@gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files \(the "Software"\), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Index

- [Constants](<#constants>)
- [Variables](<#variables>)
- [func Decrypt\(key \[\]byte, data \[\]byte\) \(\[\]byte, error\)](<#Decrypt>)
- [func Encrypt\(key \[\]byte, data \[\]byte\) \(\[\]byte, error\)](<#Encrypt>)
- [func NewKey\(\) string](<#NewKey>)
- [func NewPersistenceClient\(persisterURL, bearerToken string, k Kryptograf\) \(\*Persistence, error\)](<#NewPersistenceClient>)
- [func RandomStamp\(tm ...time.Time\) string](<#RandomStamp>)
- [func ToBinaryEncryptionKey\(base64RawStdEncoding string\) \(\[\]byte, error\)](<#ToBinaryEncryptionKey>)
- [type KeyValueMap](<#KeyValueMap>)
  - [func \(m KeyValueMap\) Delete\(key string\)](<#KeyValueMap.Delete>)
  - [func \(m KeyValueMap\) ForEach\(f func\(key string, data \[\]byte\) error\) error](<#KeyValueMap.ForEach>)
  - [func \(m KeyValueMap\) Get\(key string\) \[\]byte](<#KeyValueMap.Get>)
  - [func \(m KeyValueMap\) Len\(\) int](<#KeyValueMap.Len>)
  - [func \(m KeyValueMap\) Put\(key string, data \[\]byte\) error](<#KeyValueMap.Put>)
  - [func \(m KeyValueMap\) PutSequential\(key string, data \[\]byte\) string](<#KeyValueMap.PutSequential>)
- [type Kryptograf](<#Kryptograf>)
  - [func NewKryptograf\(\) Kryptograf](<#NewKryptograf>)
- [type Persistence](<#Persistence>)
  - [func \(p \*Persistence\) LoadAll\(ctx context.Context, f func\(key string, plaintext \[\]byte, err error\) error\) error](<#Persistence.LoadAll>)
  - [func \(p \*Persistence\) SetHTTPClient\(client \*http.Client\) \*Persistence](<#Persistence.SetHTTPClient>)
  - [func \(p \*Persistence\) SetHTTPTransport\(transport \*http.Transport\) \*Persistence](<#Persistence.SetHTTPTransport>)
  - [func \(p \*Persistence\) Store\(ctx context.Context, key string, plaintext \[\]byte\) error](<#Persistence.Store>)
  - [func \(p \*Persistence\) StoreFunc\(ctx context.Context, f func\(\) \(key string, plaintext \[\]byte, err error\)\) error](<#Persistence.StoreFunc>)


## Constants

<a name="DefaultEncryptionKey"></a>

```go
const (
    DefaultEncryptionKey     string = "TfLe2CpLn6qs8t6eQmGJnFGkU8NskfcC9AWOSEFlnLY"
    DefaultPersisterEndpoint string = "http://localhost:11185"
)
```

## Variables

<a name="ErrKeyLength"></a>

```go
var (
    ErrKeyLength            error = errors.New("key length must be 16, 24 or 32 (for AES-128, AES-192 or AES-256)")
    ErrHMACValidationFailed error = errors.New("HMAC validation failed (corrupt data or wrong encryption key)")
    ErrStop                 error = errors.New("stopped processing json stream")
    ErrKeyExists            error = errors.New("key already exist in KeyValueMap")
)
```

<a name="GzipByDefault"></a>

```go
var (
    GzipByDefault bool = false
)
```

<a name="Decrypt"></a>
## func [Decrypt](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L572>)

```go
func Decrypt(key []byte, data []byte) ([]byte, error)
```

Decrypt authenticates and decrypts data using a 16, 24 or 32 byte long key \(for AES\-128\-CFB, AES\-224\-CFB or AES\-256\-CFB\). The data should start with a HMAC\-SHA256 hash \(32 bytes\) initialized with key. The hash function should hash the rest of data which includes an aes.BlockSize long IV and the AES\-CFB encrypted data. Returns clear\-data or error in case of failure. Returns anystore.ErrHMACValidationFailed when the key is wrong or the message is corrupt or tampered with.

<a name="Encrypt"></a>
## func [Encrypt](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L533>)

```go
func Encrypt(key []byte, data []byte) ([]byte, error)
```

Encrypt encrypts data using a 16, 24 or 32 byte long key \(for AES\-128\-CFB, AES\-224\-CFB or AES\-256\-CFB\). The cipher\-data is prepended with a HMAC\-SHA256 hash \(32 bytes\) and IV \(or salt if you prefer\). Same key is used for HMAC and. The format of the output data slice is:

```
b = bytes
[HMAC_of_IV_and_cipherdata_32_b][IV_16_b][cipherdata]
```

<a name="NewKey"></a>
## func [NewKey](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L513>)

```go
func NewKey() string
```

NewKey generates a 32 byte base64 encoded random string for use as an AES\-256 key. Get a new key from the command line:

```
go run github.com/sa6mwa/kryptograf/cmd/newkey@latest
```

<a name="NewPersistenceClient"></a>
## func [NewPersistenceClient](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L659>)

```go
func NewPersistenceClient(persisterURL, bearerToken string, k Kryptograf) (*Persistence, error)
```

Returns a new kryptograf.Persistence API client. Persistence is used to send a kryptograf json stream to github.com/sa6mwa/kryptografpersister. The persister is a HTTP API that consume ciphertext from a KeyValueMap \(map\[string\]\[\]byte\) json stream \(e.g EncryptToJson or SendFunc\) and store in an AnystoreDB. The server \(persister\) does not know of the client's key and can therefore not decrypt or validate the ciphertext. Keys can be retrieved from the server via GET requests and will be seamlessly decrypted using this Persistence client.

```
newKey := kryptograf.NewKey()
k, err := kryptograf.NewKryptograf().EnableGzip().SetEncryptionKey(newKey)
if err != nil {
	panic(err)
}
// Assume kryptografpersister is running on http://localhost:11185
pc, err := kryptograf.NewPersistenceClient("", newKey, k)
if err != nil {
	panic(err)
}
if err := pc.Store(context.Background(), "myThing", []byte("Hello world")); err != nil {
	panic(err)
}
```

<a name="RandomStamp"></a>
## func [RandomStamp](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L615>)

```go
func RandomStamp(tm ...time.Time) string
```

RandomStamp returns time.Now\(\).UTC\(\) as time.Format "20060102T150405.999999999\_\{19 character random int63\}". If one tm is provided in the optional variadic argument, the first time.Time from the tm slice is used instead of time.Now\(\).UTC\(\). Intended usage of this function is for creating keys for a KV map\[string\]\[\]byte pair \(KeyValueMap\) sent as a json stream.

<a name="ToBinaryEncryptionKey"></a>
## func [ToBinaryEncryptionKey](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L605>)

```go
func ToBinaryEncryptionKey(base64RawStdEncoding string) ([]byte, error)
```

ToBinaryEncryptionKey takes a base64 raw standard encoded string and decodes it into a byte slice.

<a name="KeyValueMap"></a>
## type [KeyValueMap](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L232>)



```go
type KeyValueMap map[string][]byte
```

<a name="KeyValueMap.Delete"></a>
### func \(KeyValueMap\) [Delete](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L269>)

```go
func (m KeyValueMap) Delete(key string)
```

Deletes key from KeyValueMap.

<a name="KeyValueMap.ForEach"></a>
### func \(KeyValueMap\) [ForEach](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L283>)

```go
func (m KeyValueMap) ForEach(f func(key string, data []byte) error) error
```

ForEach calls function f for each key\-value pair in the KeyValueMap. If function f returns kryptograf.ErrStop it is treated as a break from the loop and ForEach will return a nil error. Any other error returned from f is passed as the output error of ForEach.

<a name="KeyValueMap.Get"></a>
### func \(KeyValueMap\) [Get](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L234>)

```go
func (m KeyValueMap) Get(key string) []byte
```



<a name="KeyValueMap.Len"></a>
### func \(KeyValueMap\) [Len](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L274>)

```go
func (m KeyValueMap) Len() int
```

Returns the length of the KeyValueMap \(number of keys\).

<a name="KeyValueMap.Put"></a>
### func \(KeyValueMap\) [Put](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L240>)

```go
func (m KeyValueMap) Put(key string, data []byte) error
```

Put stores data under key in KeyValueMap. If key already exist, Put returns kryptograf.ErrKeyExists.

<a name="KeyValueMap.PutSequential"></a>
### func \(KeyValueMap\) [PutSequential](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L253>)

```go
func (m KeyValueMap) PutSequential(key string, data []byte) string
```

PutSequential will append \_\{int\} to key \(e.g key\_1\) if key already exist in the KeyValueMap. If key\_2 exists, it will try key\_3, etc. Method returns the key used to store data \(key or key\_1, key\_2, etc\). PutSequential is not go routine safe, use sync/atomic for that.

<a name="Kryptograf"></a>
## type [Kryptograf](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L104-L225>)



```go
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
```

<a name="NewKryptograf"></a>
### func [NewKryptograf](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L299>)

```go
func NewKryptograf() Kryptograf
```

NewKryptograf returns a new kryptograf instance with the default encryption key and gzip disabled by default \(the value of kryptograf.GzipByDefault\). Use the method SetEncryptionKey to set your own encryption key \(from a base64 raw standard encoded string\).

<a name="Persistence"></a>
## type [Persistence](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L626-L634>)

Persistence API client toward server github.com/sa6mwa/kryptografpersister.

```go
type Persistence struct {
    // contains filtered or unexported fields
}
```

<a name="Persistence.LoadAll"></a>
### func \(\*Persistence\) [LoadAll](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L793>)

```go
func (p *Persistence) LoadAll(ctx context.Context, f func(key string, plaintext []byte, err error) error) error
```

LoadAll creates a new http request with ctx and calls function f for every decrypted key\-value pair returned by the server. The logic of function f is the same as RecvFunc, refer to the RecvFunc documentation for further information.

<a name="Persistence.SetHTTPClient"></a>
### func \(\*Persistence\) [SetHTTPClient](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L685>)

```go
func (p *Persistence) SetHTTPClient(client *http.Client) *Persistence
```

SetHTTPClient can be used to replace the default http.Client used by the Persistence client.

<a name="Persistence.SetHTTPTransport"></a>
### func \(\*Persistence\) [SetHTTPTransport](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L691>)

```go
func (p *Persistence) SetHTTPTransport(transport *http.Transport) *Persistence
```

SetHTTPTransport replaces the http.Client Transport.

<a name="Persistence.Store"></a>
### func \(\*Persistence\) [Store](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L699>)

```go
func (p *Persistence) Store(ctx context.Context, key string, plaintext []byte) error
```

Store persists a single key\-value pair in the persister.

<a name="Persistence.StoreFunc"></a>
### func \(\*Persistence\) [StoreFunc](<https://github.com/sa6mwa/kryptograf/blob/main/kryptograf.go#L747>)

```go
func (p *Persistence) StoreFunc(ctx context.Context, f func() (key string, plaintext []byte, err error)) error
```

StoreFunc persists one or multiple key\-value pairs in the persister. Request is ended when function f returns kryptograf.ErrStop or other error \(uses SendFunc underneath\). If function f returns a nil error it sends the key and plaintext, any error including ErrStop discards any key and plaintext return values.

# newkey

```go
import "github.com/sa6mwa/kryptograf/cmd/newkey"
```

## Index



# crand

```go
import "github.com/sa6mwa/kryptograf/internal/pkg/crand"
```

## Index

- [func ExpFloat64\(\) float64](<#ExpFloat64>)
- [func Float32\(\) float32](<#Float32>)
- [func Float64\(\) float64](<#Float64>)
- [func Int\(\) int](<#Int>)
- [func Int31\(\) int32](<#Int31>)
- [func Int31n\(n int32\) int32](<#Int31n>)
- [func Int63\(\) int64](<#Int63>)
- [func Int63n\(n int64\) int64](<#Int63n>)
- [func Intn\(n int\) int](<#Intn>)
- [func NormFloat64\(\) float64](<#NormFloat64>)
- [func Perm\(n int\) \[\]int](<#Perm>)
- [func Read\(p \[\]byte\) \(n int, err error\)](<#Read>)
- [func ReadRunes\(p \[\]rune\) \(n int, err error\)](<#ReadRunes>)
- [func Seed\(seed int64\)](<#Seed>)
- [func Shuffle\(n int, swap func\(i, j int\)\)](<#Shuffle>)
- [func Uint32\(\) uint32](<#Uint32>)
- [func Uint64\(\) uint64](<#Uint64>)


<a name="ExpFloat64"></a>
## func [ExpFloat64](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L76>)

```go
func ExpFloat64() float64
```



<a name="Float32"></a>
## func [Float32](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L70>)

```go
func Float32() float32
```



<a name="Float64"></a>
## func [Float64](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L69>)

```go
func Float64() float64
```



<a name="Int"></a>
## func [Int](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L65>)

```go
func Int() int
```



<a name="Int31"></a>
## func [Int31](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L64>)

```go
func Int31() int32
```



<a name="Int31n"></a>
## func [Int31n](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L67>)

```go
func Int31n(n int32) int32
```



<a name="Int63"></a>
## func [Int63](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L61>)

```go
func Int63() int64
```



<a name="Int63n"></a>
## func [Int63n](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L66>)

```go
func Int63n(n int64) int64
```



<a name="Intn"></a>
## func [Intn](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L68>)

```go
func Intn(n int) int
```



<a name="NormFloat64"></a>
## func [NormFloat64](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L75>)

```go
func NormFloat64() float64
```



<a name="Perm"></a>
## func [Perm](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L71>)

```go
func Perm(n int) []int
```



<a name="Read"></a>
## func [Read](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L73>)

```go
func Read(p []byte) (n int, err error)
```



<a name="ReadRunes"></a>
## func [ReadRunes](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L74>)

```go
func ReadRunes(p []rune) (n int, err error)
```



<a name="Seed"></a>
## func [Seed](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L60>)

```go
func Seed(seed int64)
```

These functions are frontends to math/rand...

<a name="Shuffle"></a>
## func [Shuffle](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L72>)

```go
func Shuffle(n int, swap func(i, j int))
```



<a name="Uint32"></a>
## func [Uint32](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L62>)

```go
func Uint32() uint32
```



<a name="Uint64"></a>
## func [Uint64](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/crand/crand.go#L63>)

```go
func Uint64() uint64
```



# tokenauth

```go
import "github.com/sa6mwa/kryptograf/internal/pkg/tokenauth"
```

## Index

- [type Injector](<#Injector>)
  - [func \(t \*Injector\) RoundTrip\(r \*http.Request\) \(\*http.Response, error\)](<#Injector.RoundTrip>)


<a name="Injector"></a>
## type [Injector](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/tokenauth/tokenauth.go#L7-L10>)

Injector is accessed by Injector\_RoundTrip to inject an Authorization Bearer token on every HTTP request.

```go
type Injector struct {
    Token             string
    OriginalTransport http.RoundTripper
}
```

<a name="Injector.RoundTrip"></a>
### func \(\*Injector\) [RoundTrip](<https://github.com/sa6mwa/kryptograf/blob/main/internal/pkg/tokenauth/tokenauth.go#L28>)

```go
func (t *Injector) RoundTrip(r *http.Request) (*http.Response, error)
```

Implements the http.RoundTripper interface injecting an Authorization: Bearer token header with every http request. Example:

```
c := http.Client{}
c.Timeout = 10 * time.Second
c.Transport = &authtoken.Injector{Token: "secret", OriginalTransport: c.Transport}
```

Generated by [gomarkdoc](<https://github.com/princjef/gomarkdoc>)
