package kryptograf_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sa6mwa/kryptograf"
)

type Msg struct {
	Msg string `json:"message"`
}

func toJson(v any) []byte {
	j, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte("{}")
	}
	return j
}

func TestNewKryptograf(t *testing.T) {
	k := kryptograf.NewKryptograf()
	defaultEncryptionKey, err := base64.RawStdEncoding.DecodeString(kryptograf.DefaultEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(k.GetEncryptionKey(), defaultEncryptionKey) != 0 {
		t.Errorf("%x does not match %x", k.GetEncryptionKey(), defaultEncryptionKey)
	}
}

func TestKryptograf_SetEncryptionKey(t *testing.T) {
	newKey := kryptograf.NewKey()
	binKey, err := kryptograf.ToBinaryEncryptionKey(newKey)
	if err != nil {
		t.Fatal(err)
	}
	k, err := kryptograf.NewKryptograf().SetEncryptionKey(newKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(k.GetEncryptionKey(), binKey) != 0 {
		t.Errorf("%x does not match %x", k.GetEncryptionKey(), newKey)
	}
}

func TestKryptograf_EnableGzip(t *testing.T) {
	k := kryptograf.NewKryptograf().EnableGzip()
	if !k.Gzip() {
		t.Error("gzip is turned off when it should be on")
	}
	k.DisableGzip()
	if k.Gzip() {
		t.Error("gzip is turned on when it should be off")
	}
}

func TestKryptograf_Encrypt(t *testing.T) {
	k, err := kryptograf.NewKryptograf().SetEncryptionKey(kryptograf.NewKey())
	if err != nil {
		t.Fatal(err)
	}
	testData := []bool{false, true}
	for _, doGzip := range testData {
		if doGzip {
			k.EnableGzip()
		}
		msg := "Hello world"
		ciphertext, err := k.Encrypt([]byte(msg))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("gzip=%t length=%d key=%x ciphertext=%x", k.Gzip(), len(ciphertext), k.GetEncryptionKey(), ciphertext)
		plaintext, err := k.Decrypt(ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Compare([]byte(msg), plaintext) != 0 {
			t.Errorf("%q does not match %q", []byte(msg), plaintext)
		}
	}
}

func TestKryptograf_Decrypt(t *testing.T) {
	uncoveredMessage := "Hello world"
	binKey, err := hex.DecodeString(`974089a82b9602c69d53707d59a7be56e4095af0f958a61078879bc84e7bdab8`)
	if err != nil {
		t.Fatal(err)
	}
	base64key := base64.RawStdEncoding.EncodeToString(binKey)
	ciphertext, err := hex.DecodeString(`1c053a1041a4346c50ab7b124f6731f30c93c428ebf622d92c272d4661cc67b0c5a7b8a9728395a19514e7fe76a3dd7a91238f6d39e753a0624028`)
	if err != nil {
		t.Fatal(err)
	}
	k, err := kryptograf.NewKryptograf().SetEncryptionKey(base64key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := k.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(plaintext, []byte(uncoveredMessage)) != 0 {
		t.Errorf("%q does not match %q", []byte(uncoveredMessage), plaintext)
	}
}

func TestEncrypt(t *testing.T) {
	encTestFunc := func(key []byte, data []byte) {
		t.Logf("Testing %d bytes long key", len(key))
		mac := hmac.New(sha256.New, key)
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		if aes.BlockSize != block.BlockSize() {
			t.Errorf("aes.BlockSize != block.BlockSize(), but %d and %d respectively", aes.BlockSize, block.BlockSize())
		}
		t.Logf("mac.Size() = %d", mac.Size())
		t.Logf("aes.BlockSize = %d", aes.BlockSize)
		t.Logf("block.BlockSize = %d", block.BlockSize())
		encrypted, err := kryptograf.Encrypt(key, data)
		if err != nil {
			t.Fatal(err)
		}
		if len(encrypted) < mac.Size()+aes.BlockSize {
			t.Fatalf("length of enciphered data is less than mac.Size()+aes.BlockSize (want>%d, got %d)", mac.Size()+aes.BlockSize, len(encrypted))
		}
		// Get HMAC from cipher-text
		encryptedHMAC := encrypted[:mac.Size()]
		message := encrypted[mac.Size():]
		//iv := encrypted[mac.Size() : mac.Size()+aes.BlockSize]
		//cipherText := encrypted[mac.Size()+aes.BlockSize:]
		if _, err := mac.Write(message); err != nil {
			t.Fatal(err)
		}
		if !hmac.Equal(encryptedHMAC, mac.Sum(nil)) {
			t.Fatal(kryptograf.ErrHMACValidationFailed)
		}
		// Decrypt must also work
		decrypted, err := kryptograf.Decrypt(key, encrypted)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, decrypted) {
			t.Logf("origidata=%v", data)
			t.Logf("decrypted=%v", decrypted)
			t.Fatal("original data and decrypted data (from encryption) does not match")
		}
	}

	key, err := kryptograf.ToBinaryEncryptionKey(kryptograf.NewKey())
	if err != nil {
		t.Fatal(err)
	}

	if len(key) != 32 {
		t.Fatalf("expected NewKey() to produce a 32 byte long key, but got %d bytes", len(key))
	}

	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
	keys := [][]byte{key, key[:24], key[:16]}
	for _, k := range keys {
		encTestFunc(k, data)
	}
}

func TestDecrypt(t *testing.T) {
	decrypTestFunc := func(key []byte, data []byte) {
		t.Logf("Testing %d bytes long key", len(key))
		mac := hmac.New(sha256.New, key)
		if len(data) < mac.Size()+aes.BlockSize {
			t.Fatalf("length of cipher data is less than mac.Size()+aes.BlockSize (want>%d, got %d)", mac.Size()+aes.BlockSize, len(data))
		}
		messageWithIV := data[mac.Size():]
		t.Logf("mac.Size() == %d", mac.Size())
		t.Logf("data is %d bytes long, w/o HMAC == %d", len(data), len(messageWithIV))
		messageHMAC := data[:mac.Size()]
		if _, err := mac.Write(messageWithIV); err != nil {
			t.Fatal(err)
		}
		if !hmac.Equal(messageHMAC, mac.Sum(nil)) {
			t.Fatal(kryptograf.ErrHMACValidationFailed)
		}
	}

	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
	key, err := kryptograf.ToBinaryEncryptionKey(kryptograf.NewKey())
	if err != nil {
		t.Fatal(err)
	}

	for _, k := range [][]byte{key, key[:24], key[:16]} {
		ciphered, err := kryptograf.Encrypt(k, data)
		if err != nil {
			t.Fatal(err)
		}
		decrypTestFunc(k, ciphered)
	}
}

func TestKryptograf_Recv(t *testing.T) {
	testData := []string{"Hello world", "Message number 2 is a bit longer."}
	k := kryptograf.NewKryptograf()
	for _, msg := range testData {
		ciphertext, err := k.Encrypt([]byte(msg))
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := k.Recv(bytes.NewReader(ciphertext))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Compare(plaintext, []byte(msg)) != 0 {
			t.Errorf("%q does not match %q", []byte(msg), plaintext)
		}
	}
}

func TestKryptograf_Send(t *testing.T) {
	var output bytes.Buffer
	k := kryptograf.NewKryptograf()
	msg := []byte("Hello world, sent to the third ball from the sun.")
	if err := k.Send(msg, &output); err != nil {
		t.Fatal(err)
	}
	plaintext, err := k.Recv(&output)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(msg, plaintext) != 0 {
		t.Errorf("%q does not equal %q", output.Bytes(), msg)
	}
}

func TestKryptograf_EncryptToString(t *testing.T) {
	msg := "Hello world; that is the message sent to the third sphere from the sun."
	k := kryptograf.NewKryptograf()
	str, err := k.EncryptToString([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	byts, err := k.DecryptString(str)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare([]byte(msg), byts) != 0 {
		t.Errorf("expected %q, but got %q", msg, byts)
	}
}

func TestKryptograf_DecryptString(t *testing.T) {
	ciphertextString := `2RvkTt3QhJpN3gcRLXsJsBIlaqoXc8PoqAxSOleYu+mN4UihC1eSiGDYid9HFFhGgNFpKcS5zcc2bMFPJYaKz6O+QTg3MAyVBeIb4xbd8Cxp15rjk2keVbUfUUTRss368r8xYamQu2YoVsLzTDRvfW0eajYudIQ`
	expectedString := "Hello world; that is the message sent to the third sphere from the sun."
	k := kryptograf.NewKryptograf()
	plaintext, err := k.DecryptString(ciphertextString)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare([]byte(expectedString), plaintext) != 0 {
		t.Errorf("expected %q, but got %q", expectedString, plaintext)
	}
}

func TestKryptograf_RecvFromJson(t *testing.T) {
	testJsonSingle := `{"msg1":"HAU6EEGkNGxQq3sST2cx8wyTxCjr9iLZLCctRmHMZ7DFp7ipcoOVoZUU5/52o916kSOPbTnnU6BiQCg="}`

	testJsonMultiple :=
		`{"msg1":"HAU6EEGkNGxQq3sST2cx8wyTxCjr9iLZLCctRmHMZ7DFp7ipcoOVoZUU5/52o916kSOPbTnnU6BiQCg="}` + "\n" +
			`{"msg2":"HAU6EEGkNGxQq3sST2cx8wyTxCjr9iLZLCctRmHMZ7DFp7ipcoOVoZUU5/52o916kSOPbTnnU6BiQCg="}` + "\n" +
			`{"msg3":"HAU6EEGkNGxQq3sST2cx8wyTxCjr9iLZLCctRmHMZ7DFp7ipcoOVoZUU5/52o916kSOPbTnnU6BiQCg="}` + "\n" +
			`{"msg4":"HAU6EEGkNGxQq3sST2cx8wyTxCjr9iLZLCctRmHMZ7DFp7ipcoOVoZUU5/52o916kSOPbTnnU6BiQCg="}` + "\n" +
			`{"msg5":"HAU6EEGkNGxQq3sST2cx8wyTxCjr9iLZLCctRmHMZ7DFp7ipcoOVoZUU5/52o916kSOPbTnnU6BiQCg="}` + "\n" +
			`{"msg6":"HAU6EEGkNGxQq3sST2cx8wyTxCjr9iLZLCctRmHMZ7DFp7ipcoOVoZUU5/52o916kSOPbTnnU6BiQCg="}` + "\n"

	uncoveredMessage := "Hello world"

	binKey, err := hex.DecodeString(`974089a82b9602c69d53707d59a7be56e4095af0f958a61078879bc84e7bdab8`)
	if err != nil {
		t.Fatal(err)
	}
	base64key := base64.RawStdEncoding.EncodeToString(binKey)
	k, err := kryptograf.NewKryptograf().SetEncryptionKey(base64key)
	if err != nil {
		t.Fatal(err)
	}

	messages := make(map[string][]byte)

	j := json.NewDecoder(strings.NewReader(testJsonSingle))
	for {
		kv, err := k.RecvFromJson(j, true)
		if err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		for key, val := range kv {
			messages[key] = val
		}
	}
	if len(messages) != 1 {
		t.Errorf("expected one key in map, got %d keys", len(messages))
	}
	if bytes.Compare(messages["msg1"], []byte(uncoveredMessage)) != 0 {
		t.Errorf("%x does not equal %x", messages["msg1"], []byte(uncoveredMessage))
	}

	j = json.NewDecoder(strings.NewReader(testJsonMultiple))
	for {
		kv, err := k.RecvFromJson(j, true)
		if err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		for key, val := range kv {
			messages[key] = val
		}
	}
	if len(messages) != 6 {
		t.Errorf("expected 6 keys in map, got %d", len(messages))
	}
	for key, plaintext := range messages {
		switch key {
		case "msg1", "msg2", "msg3", "msg4", "msg5", "msg6":
		default:
			t.Errorf("expected keys msg1-6, but got %q", key)
		}
		if bytes.Compare(plaintext, []byte(uncoveredMessage)) != 0 {
			t.Errorf("%x does not equal %x", plaintext, []byte(uncoveredMessage))
		}
	}
}

func TestKryptograf_EncryptToJson(t *testing.T) {
	uncoveredMessage := "Hello world"
	testMessages := make(map[string][]byte)
	testMessages["msg1"] = []byte(uncoveredMessage + " 1")
	testMessages["msg2"] = []byte(uncoveredMessage + " 2")
	testMessages["msg3"] = []byte(uncoveredMessage + " 3")

	binKey, err := hex.DecodeString(`974089a82b9602c69d53707d59a7be56e4095af0f958a61078879bc84e7bdab8`)
	if err != nil {
		t.Fatal(err)
	}
	base64key := base64.RawStdEncoding.EncodeToString(binKey)
	k, err := kryptograf.NewKryptograf().SetEncryptionKey(base64key)
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := k.EncryptToJson(testMessages, &output); err != nil {
		t.Fatal(err)
	}

	plaintextMessages := make(map[string][]byte)
	j := json.NewDecoder(bytes.NewReader(output.Bytes()))
	for {
		msg, err := k.RecvFromJson(j, true)
		if err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		for key, val := range msg {
			plaintextMessages[key] = val
		}
	}

	if len(plaintextMessages) != 3 {
		t.Errorf("expected 3 keys in the output, but got %d", len(plaintextMessages))
	}

	for i := 0; i < len(plaintextMessages); i++ {
		key := fmt.Sprintf("msg%d", i+1)
		msg := []byte(fmt.Sprintf("Hello world %d", i+1))
		if bytes.Compare(plaintextMessages[key], msg) != 0 {
			t.Errorf("value of key %q is %q, expected %q", key, plaintextMessages[key], msg)
		}
	}
}

func TestKryptograf_RecvFunc(t *testing.T) {
	testJsonSingle := `{"msg1":"HAU6EEGkNGxQq3sST2cx8wyTxCjr9iLZLCctRmHMZ7DFp7ipcoOVoZUU5/52o916kSOPbTnnU6BiQCg="}`

	testJsonMultiple :=
		`{"msg1":"HAU6EEGkNGxQq3sST2cx8wyTxCjr9iLZLCctRmHMZ7DFp7ipcoOVoZUU5/52o916kSOPbTnnU6BiQCg="}` + "\n" +
			`{"msg2":"HAU6EEGkNGxQq3sST2cx8wyTxCjr9iLZLCctRmHMZ7DFp7ipcoOVoZUU5/52o916kSOPbTnnU6BiQCg="}` + "\n" +
			`{"msg3":"HAU6EEGkNGxQq3sST2cx8wyTxCjr9iLZLCctRmHMZ7DFp7ipcoOVoZUU5/52o916kSOPbTnnU6BiQCg="}` + "\n" +
			`{"msg4":"HAU6EEGkNGxQq3sST2cx8wyTxCjr9iLZLCctRmHMZ7DFp7ipcoOVoZUU5/52o916kSOPbTnnU6BiQCg="}` + "\n" +
			`{"msg5":"HAU6EEGkNGxQq3sST2cx8wyTxCjr9iLZLCctRmHMZ7DFp7ipcoOVoZUU5/52o916kSOPbTnnU6BiQCg="}` + "\n" +
			`{"msg6":"HAU6EEGkNGxQq3sST2cx8wyTxCjr9iLZLCctRmHMZ7DFp7ipcoOVoZUU5/52o916kSOPbTnnU6BiQCg="}` + "\n"

	uncoveredMessage := "Hello world"

	binKey, err := hex.DecodeString(`974089a82b9602c69d53707d59a7be56e4095af0f958a61078879bc84e7bdab8`)
	if err != nil {
		t.Fatal(err)
	}
	base64key := base64.RawStdEncoding.EncodeToString(binKey)
	k, err := kryptograf.NewKryptograf().SetEncryptionKey(base64key)
	if err != nil {
		t.Fatal(err)
	}

	if err := k.RecvFunc(strings.NewReader(testJsonSingle), func(key string, plaintext []byte, err error) error {
		if got, expected := key, "msg1"; got != expected {
			t.Errorf("Expected key %q, got %q", expected, got)
		}
		if got, expected := plaintext, []byte(uncoveredMessage); bytes.Compare(got, expected) != 0 {
			t.Errorf("Expected %v, got %v", expected, got)
		}
		return kryptograf.ErrStop
	}); err != nil {
		t.Error(err)
	}

	testFunc := func(maximum int) {
		count := 0
		if err := k.RecvFunc(strings.NewReader(testJsonMultiple), func(key string, plaintext []byte, err error) error {
			count++
			t.Log("key:", key, "plaintext:", string(plaintext))
			if got, expected := key, fmt.Sprintf("msg%d", count); got != expected {
				t.Errorf("Expected key %q, got %q", expected, got)
			}
			if got, expected := plaintext, []byte(uncoveredMessage); bytes.Compare(got, expected) != 0 {
				t.Errorf("Expected %v, got %v", expected, got)
			}
			if count >= maximum {
				return kryptograf.ErrStop
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
		if got, expected := count, maximum; got != expected {
			t.Errorf("Expected %d, got %d", expected, got)
		}
	}

	testFunc(6)
	testFunc(3)
}

func TestKryptograf_SendFunc(t *testing.T) {
	testJsonSingle := map[string][]byte{
		"msg1": []byte("Hello world"),
	}

	testJsonMultiple := map[string][]byte{
		"msg1": []byte("Hello world one"),
		"msg2": []byte("Hello world two"),
		"msg3": []byte("Hello world three"),
		"msg4": []byte("Hello world four"),
		"msg5": []byte("Hello world five"),
		"msg6": []byte("Hello world six"),
	}

	binKey, err := hex.DecodeString(`974089a82b9602c69d53707d59a7be56e4095af0f958a61078879bc84e7bdab8`)
	if err != nil {
		t.Fatal(err)
	}
	base64key := base64.RawStdEncoding.EncodeToString(binKey)
	k, err := kryptograf.NewKryptograf().SetEncryptionKey(base64key)
	if err != nil {
		t.Fatal(err)
	}

	testFunc := func(out io.Writer, input map[string][]byte, maximum int) {
		count := 0
		if err := k.SendFunc(out, func() (key string, plaintext []byte, err error) {
			count++
			if count > maximum {
				err = kryptograf.ErrStop
				return
			}
			key = fmt.Sprintf("msg%d", count)
			plaintext = input[key]
			return
		}); err != nil {
			t.Error(err)
		}
	}

	var output1 bytes.Buffer
	var output2 bytes.Buffer
	var output3 bytes.Buffer
	testFunc(&output1, testJsonSingle, 1)
	testFunc(&output2, testJsonMultiple, 6)
	testFunc(&output3, testJsonMultiple, 3)

	t.Log("testJsonSingle:", output1.String())
	t.Log("testJsonMultiple-6:", output2.String())
	t.Log("testJsonMultiple-3:", output3.String())

	assertFunc := func(in io.Reader, uncovered map[string][]byte, maximum int) {
		count := 0
		if err := k.RecvFunc(in, func(key string, plaintext []byte, err error) error {
			count++
			t.Log("key:", key, "plaintext:", string(plaintext))
			if got, expected := key, fmt.Sprintf("msg%d", count); got != expected {
				t.Errorf("Expected key %q, got %q", expected, got)
			}
			if got, expected := plaintext, []byte(uncovered[key]); bytes.Compare(got, expected) != 0 {
				t.Errorf("Expected %v, got %v", expected, got)
			}
			if count >= maximum {
				return kryptograf.ErrStop
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
		if got, expected := count, maximum; got != expected {
			t.Errorf("Expected %d, got %d", expected, got)
		}
	}

	assertFunc(&output1, testJsonSingle, 1)
	assertFunc(&output2, testJsonMultiple, 6)
	assertFunc(&output3, testJsonMultiple, 3)

}

func TestRandomStamp(t *testing.T) {
	tm := time.Now()
	rs := []string{
		kryptograf.RandomStamp(),
		kryptograf.RandomStamp(),
		kryptograf.RandomStamp(tm),
		kryptograf.RandomStamp(tm),
	}
	for _, r := range rs {
		t.Log("RandomStamp:", r)
		count := 0
		for _, inner := range rs {
			if r == inner {
				count++
			}
		}
		if got, expected := count, 1; got != expected {
			t.Errorf("Expected %d, got %d matches (not random enough)", expected, got)
		}
	}
}

func TestPersistence_Store(t *testing.T) {
	k, err := kryptograf.NewKryptograf().SetEncryptionKey(kryptograf.DefaultEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		defer r.Body.Close()
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		if err != nil {
			t.Log(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(toJson(Msg{Msg: err.Error()}))
			return
		}
		t.Log(string(body))
		if err := k.RecvFunc(r.Body, func(key string, plaintext []byte, err error) error {
			if err == io.EOF {
				return kryptograf.ErrStop
			}
			t.Log("key:", key, "plaintext:", string(plaintext))
			if got, expected := key, "test"; got != expected {
				t.Errorf("Expected key %q, got %q", expected, got)
			}
			if got, expected := string(plaintext), "Hello world"; got != expected {
				t.Errorf("Expected string %q, got %q", expected, got)
			}
			return nil
		}); err != nil {
			t.Log(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(toJson(Msg{Msg: err.Error()}))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(toJson(Msg{Msg: "OK"}))
	}))

	//s.URL = "http://localhost:11185"

	p, err := kryptograf.NewPersistenceClient(s.URL, "", k)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Store(context.Background(), "test", []byte("Hello world")); err != nil {
		t.Fatal(err)
	}
}

func TestPersistence_StoreFunc(t *testing.T) {
	k, err := kryptograf.NewKryptograf().SetEncryptionKey(kryptograf.DefaultEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		defer r.Body.Close()
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		if err != nil {
			t.Log(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(toJson(Msg{Msg: err.Error()}))
			return
		}
		t.Log(string(body))
		i := 1
		if err := k.RecvFunc(r.Body, func(key string, plaintext []byte, err error) error {
			if err == io.EOF {
				return kryptograf.ErrStop
			}
			t.Log("key:", key, "plaintext:", string(plaintext))
			switch i {
			case 1:
				if got, expected := key, "key1"; got != expected {
					t.Errorf("Expected key %q, got %q", expected, got)
				}
				if got, expected := string(plaintext), "Hello world one"; got != expected {
					t.Errorf("Expected string %q, got %q", expected, got)
				}
			case 2:
				if got, expected := key, "key2"; got != expected {
					t.Errorf("Expected key %q, got %q", expected, got)
				}
				if got, expected := string(plaintext), "Hello world two"; got != expected {
					t.Errorf("Expected string %q, got %q", expected, got)
				}
			case 3:
				if got, expected := key, "key3"; got != expected {
					t.Errorf("Expected key %q, got %q", expected, got)
				}
				if got, expected := string(plaintext), "Hello world three"; got != expected {
					t.Errorf("Expected string %q, got %q", expected, got)
				}
			default:
				t.Errorf("Did not expected key %q and plaintext %q", key, string(plaintext))
			}
			i++
			return nil
		}); err != nil {
			t.Log(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(toJson(Msg{Msg: err.Error()}))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(toJson(Msg{Msg: "OK"}))
	}))

	//s.URL = "http://localhost:11185"

	p, err := kryptograf.NewPersistenceClient(s.URL, "", k)
	if err != nil {
		t.Fatal(err)
	}
	ts := []map[string][]byte{
		{"key1": []byte("Hello world one")},
		{"key2": []byte("Hello world two")},
		{"key3": []byte("Hello world three")},
	}
	count := 0
	nextKV := func() (string, []byte, error) {
		if count >= len(ts) {
			return "", nil, kryptograf.ErrStop
		}
		for k, v := range ts[count] {
			count++
			return k, v, nil
		}
		return "", nil, errors.New("no key-value pairs")
	}
	if err := p.StoreFunc(context.Background(), func() (string, []byte, error) {
		return nextKV()
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPersistence_LoadAll(t *testing.T) {
	testdata := `{"key1":"E1HptIyOYxEu34vkp4MVSBrZyA9/DqhmPtirLjBRlPr/ZQfJ3yaqi4NaTtLuRGxc+4PaPOEVlbl+Dr2pw9qj"} {"key2":"DkF0UmMnLSAqWzPAoOWJWiZV7KDJ2RFhdARaouMTf1CCUhPvWngBYJo04RLrpEGjgKkHn0pIgiQzY2rE5Sv/"}
{"key3":"Y+G91MdhaRDekq3gWa8RXNIyztM3K8IPfDLNDNaqlpXCvu/phMrAxbiEJwMJ2FS648TegEpnoESZ/ZZCNB0G6Ls="}`

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if got, expected := token, "Bearer HelloWorld"; got != expected {
			t.Errorf("Expected Authorization header to be %q, but got %q", expected, got)
		}
		defer r.Body.Close()
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(testdata))
			return
		default:
			t.Errorf("Method %q not supported by test server", r.Method)
			w.WriteHeader(http.StatusBadRequest)
			w.Write(toJson(Msg{Msg: "bad request"}))
			return
		}
	}))

	//s.URL = "http://localhost:11185"

	k, err := kryptograf.NewKryptograf().SetEncryptionKey(kryptograf.DefaultEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	p, err := kryptograf.NewPersistenceClient(s.URL, "HelloWorld", k)
	if err != nil {
		t.Fatal(err)
	}

	gots := []bool{false, false, false}
	if err := p.LoadAll(context.Background(), func(key string, plaintext []byte, err error) error {
		if err == io.EOF {
			return kryptograf.ErrStop
		}
		switch key {
		case "key1":
			if got, expected := string(plaintext), "Hello world one"; got != expected {
				t.Errorf("Expected %q, but got %q for %q", expected, got, key)
			}
			gots[0] = true
		case "key2":
			if got, expected := string(plaintext), "Hello world two"; got != expected {
				t.Errorf("Expected %q, but got %q for %q", expected, got, key)
			}
			gots[1] = true
		case "key3":
			if got, expected := string(plaintext), "Hello world three"; got != expected {
				t.Errorf("Expected %q, but got %q for %q", expected, got, key)
			}
			gots[2] = true
		default:
			t.Errorf("Did not expect key %q with plaintext %q", key, string(plaintext))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for i, got := range gots {
		if !got {
			t.Errorf("Expected to have gotten result index %d, but it's marked %v", i, got)
		}
	}
}
