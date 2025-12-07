package kryptograf

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"pkt.systems/kryptograf/cipher"
	"pkt.systems/kryptograf/keymgmt"
)

// deterministicMaterial provides reproducible root/material pairs for examples.
// In production, use MintDEK/EnsureDescriptor instead.
func deterministicMaterial(label string) (keymgmt.RootKey, keymgmt.Material) {
	rootDigest := sha256.Sum256([]byte("root:" + label))
	var root keymgmt.RootKey
	copy(root[:], rootDigest[:])

	keyDigest := sha256.Sum256([]byte("dek:" + label))
	var key keymgmt.DEK
	copy(key[:], keyDigest[:])

	saltDigest := sha256.Sum256([]byte("salt:" + label))
	var salt [32]byte
	copy(salt[:], saltDigest[:])

	contextDigest := sha256.Sum256([]byte("context:" + label))

	nonceDigest := sha256.Sum256([]byte("nonce:" + label))
	var nonce [32]byte
	copy(nonce[:], nonceDigest[:])

	material := keymgmt.Material{
		Key: key,
		Descriptor: keymgmt.Descriptor{
			Version:       2,
			HKDFHash:      1,
			NonceSize:     12,
			Salt:          salt,
			ContextDigest: contextDigest,
		},
	}
	copy(material.Descriptor.Nonce[:], nonce[:])

	return root, material
}

func Example_encryptPipe() {
	// Production setup (for reference):
	//	store, err := Load("bundle.pem")
	//	if err != nil {
	//		panic(err)
	//	}
	//	root, err := store.EnsureRootKey()
	//	if err != nil {
	//		panic(err)
	//	}
	//	material, err := store.EnsureDescriptor("example", root, []byte("example"))
	//	if err != nil {
	//		panic(err)
	//	}
	//	if err := store.Commit(); err != nil {
	//		panic(err)
	//	}

	root, mat := deterministicMaterial("pipe-example")
	kg := New(root)

	inf := bytes.NewBufferString("Hello world")

	cipherReader, plainWriter, err := kg.NewEncryptPipe(mat)
	if err != nil {
		panic(err)
	}

	var ciphertext bytes.Buffer
	go func() {
		defer plainWriter.Close()
		io.Copy(plainWriter, inf)
	}()

	// Drain ciphertext into a buffer.
	if _, err := io.Copy(&ciphertext, cipherReader); err != nil {
		panic(err)
	}

	// Decrypt from the buffered ciphertext.
	decryptedReader, err := kg.DecryptReader(bytes.NewReader(ciphertext.Bytes()), mat)
	if err != nil {
		panic(err)
	}
	buf, _ := io.ReadAll(decryptedReader)
	decryptedReader.Close()

	fmt.Printf("Plaintext: %s\n", "Hello world")
	fmt.Printf("Decrypted: %s\n", string(buf))

	// Output:
	// Plaintext: Hello world
	// Decrypted: Hello world
}

func Example_encryptWriter() {
	// Production setup (for reference):
	//	store, err := Load("bundle.pem")
	//	if err != nil {
	//		panic(err)
	//	}
	//	root, err := store.EnsureRootKey()
	//	if err != nil {
	//		panic(err)
	//	}
	//	material, err := store.EnsureDescriptor("file-id", root, []byte("file-id"))
	//	if err != nil {
	//		panic(err)
	//	}
	//	if err := store.Commit(); err != nil {
	//		panic(err)
	//	}

	root, mat := deterministicMaterial("file-write")
	kg := New(root)

	var ciphertext bytes.Buffer
	writer, err := kg.EncryptWriter(&ciphertext, mat)
	if err != nil {
		panic(err)
	}
	if _, err := io.WriteString(writer, "Hello file"); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}

	fmt.Printf("Plaintext: %s\n", "Hello file")
	fmt.Printf("Ciphertext: 0x%X\n", ciphertext.Bytes())

	// Output:
	// Plaintext: Hello file
	// Ciphertext: 0x0100000000000000000A9ACD33031BB06E4D87FB3DF10AC943527ED0F06AEFFBF433422C01010000000100000000505636405E89E0F1E7EA445CF296F3B7
}

func Example_decryptReader() {
	// Production setup (for reference):
	//	cipherReader, err := os.Open("report.txt.enc")
	//	...
	//	root, mat := store.EnsureDescriptor(...)
	//	reader, _ := kg.DecryptReader(cipherReader, mat)
	//	io.Copy(dst, reader)

	root, mat := deterministicMaterial("file-read")
	kg := New(root)

	var ciphertext bytes.Buffer
	writer, err := kg.EncryptWriter(&ciphertext, mat)
	if err != nil {
		panic(err)
	}
	io.WriteString(writer, "Decrypt me")
	writer.Close()

	reader, err := kg.DecryptReader(bytes.NewReader(ciphertext.Bytes()), mat)
	if err != nil {
		panic(err)
	}
	var plaintext bytes.Buffer
	if _, err := io.Copy(&plaintext, reader); err != nil {
		panic(err)
	}
	reader.Close()

	fmt.Printf("Ciphertext: 0x%X\n", ciphertext.Bytes())
	fmt.Printf("Plaintext: %s\n", plaintext.String())

	// Output:
	// Ciphertext: 0x0100000000000000000A29EB79EE4C56033A5FA24CCA7263883BEAD8D635D915D09C270D0101000000010000000057CEC8B4B3D63DB6C85D5E7997CA2DE3
	// Plaintext: Decrypt me
}

func Example_storeEnsureDescriptor() {
	// Production setup:
	//	store, err := Load("bundle.pem")
	//	if err != nil {
	//		panic(err)
	//	}
	//	root, err := store.EnsureRootKey()
	//	if err != nil {
	//		panic(err)
	//	}
	//	ensured, err := store.EnsureDescriptor("LOCKD", root, []byte("lockd"))
	//	if err != nil {
	//		panic(err)
	//	}
	//	if err := store.Commit(); err != nil {
	//		panic(err)
	//	}

	root, mat := deterministicMaterial("lockd")

	bundle := keymgmt.NewProtoBundle()
	bundle.SetRootKey(root)
	bundle.SetDescriptor("LOCKD", mat.Descriptor)
	data, _ := bundle.Marshal()

	store, _ := keymgmt.LoadProto(data)
	ensured, _ := store.EnsureDescriptor("LOCKD", root, []byte("lockd"))

	fmt.Printf("nonce bytes: %d\n", ensured.Descriptor.NonceBytes())
	fmt.Printf("salt prefix: %X\n", ensured.Descriptor.Salt[:2])

	// Output:
	// nonce bytes: 12
	// salt prefix: 0000
}

func Example_materialHex() {
	// Production usage:
	//	mat, err := kg.MintDEK([]byte("ctx"))
	//	if err != nil {
	//		panic(err)
	//	}
	//	fmt.Println(mat.Key.EncodeToHex())
	//	descHex, _ := mat.Descriptor.EncodeToHex()
	//	fmt.Println(descHex)

	_, mat := deterministicMaterial("hex-demo")

	fmt.Println(mat.Key.EncodeToHex())
	descHex, _ := mat.Descriptor.EncodeToHex()
	fmt.Println(descHex[:16])

	// Output:
	// dc595e5d77837557370d30b8a183f2a93a32320b2bce48b2da7c1aa8391d2610
	// 02010cd81b7a9377
}

func TestKryptografRoundTrip(t *testing.T) {
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey error: %v", err)
	}

	kg := New(root).WithChunkSize(32 * 1024)
	mat, err := kg.MintDEK([]byte("roundtrip"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}

	var buf bytes.Buffer
	writer, err := kg.EncryptWriter(&buf, mat)
	if err != nil {
		t.Fatalf("EncryptWriter error: %v", err)
	}

	payload := bytes.Repeat([]byte("kryptograf "), 1024)
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	recovered, err := kg.ReconstructDEK([]byte("roundtrip"), mat.Descriptor)
	if err != nil {
		t.Fatalf("ReconstructDEK error: %v", err)
	}

	reader, err := kg.DecryptReader(bytes.NewReader(buf.Bytes()), recovered)
	if err != nil {
		t.Fatalf("DecryptReader error: %v", err)
	}
	defer reader.Close()

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}

	if !bytes.Equal(out, payload) {
		t.Fatalf("payload mismatch after roundtrip")
	}
}

func TestKryptografPipes(t *testing.T) {
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey error: %v", err)
	}
	kg := New(root).WithGzip()

	mat, err := kg.MintDEK([]byte("pipes"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}

	cipherReader, plainWriter, err := kg.NewEncryptPipe(mat)
	if err != nil {
		t.Fatalf("NewEncryptPipe error: %v", err)
	}
	defer cipherReader.Close()

	go func() {
		defer plainWriter.Close()
		_, _ = plainWriter.Write(bytes.Repeat([]byte("stream"), 4096))
	}()

	decryptedReader, cipherWriter, err := kg.NewDecryptPipe(mat)
	if err != nil {
		t.Fatalf("NewDecryptPipe error: %v", err)
	}
	defer decryptedReader.Close()

	go func() {
		defer cipherWriter.Close()
		_, _ = io.Copy(cipherWriter, cipherReader)
	}()

	got, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}

	if len(got) == 0 {
		t.Fatalf("expected plaintext from decrypt pipe")
	}
}

func TestKryptografWithChaChaCipher(t *testing.T) {
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey error: %v", err)
	}
	kg := New(root)

	mat, err := kg.MintDEK([]byte("chacha-root"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}

	var buf bytes.Buffer
	writer, err := kg.EncryptWriter(&buf, mat, WithCipher(cipher.ChaCha20Poly1305()))
	if err != nil {
		t.Fatalf("EncryptWriter error: %v", err)
	}
	if _, err := writer.Write([]byte("hello")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	reader, err := kg.DecryptReader(bytes.NewReader(buf.Bytes()), mat, WithCipher(cipher.ChaCha20Poly1305()))
	if err != nil {
		t.Fatalf("DecryptReader error: %v", err)
	}
	defer reader.Close()

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(out) != "hello" {
		t.Fatalf("unexpected plaintext: %s", string(out))
	}
}

func TestKryptografWithChaChaPerFrame(t *testing.T) {
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey error: %v", err)
	}
	kg := New(root)

	mat, err := kg.MintDEK([]byte("chacha-pf"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}

	var buf bytes.Buffer
	writer, err := kg.EncryptWriter(&buf, mat, WithCipher(cipher.ChaCha20Poly1305PerFrame()))
	if err != nil {
		t.Fatalf("EncryptWriter error: %v", err)
	}
	if _, err := writer.Write([]byte("hello")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	reader, err := kg.DecryptReader(bytes.NewReader(buf.Bytes()), mat, WithCipher(cipher.ChaCha20Poly1305PerFrame()))
	if err != nil {
		t.Fatalf("DecryptReader error: %v", err)
	}
	defer reader.Close()

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(out) != "hello" {
		t.Fatalf("unexpected plaintext: %s", string(out))
	}
}

func TestKryptografWithXChaChaCipher(t *testing.T) {
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey error: %v", err)
	}
	kg := New(root)

	mat, err := kg.MintDEKWithNonceSize([]byte("xchacha"), 24)
	if err != nil {
		t.Fatalf("MintDEKWithNonceSize error: %v", err)
	}

	var buf bytes.Buffer
	writer, err := kg.EncryptWriter(&buf, mat, WithCipher(cipher.XChaCha20Poly1305()))
	if err != nil {
		t.Fatalf("EncryptWriter error: %v", err)
	}
	if _, err := writer.Write([]byte("hello")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	reader, err := kg.DecryptReader(bytes.NewReader(buf.Bytes()), mat, WithCipher(cipher.XChaCha20Poly1305()))
	if err != nil {
		t.Fatalf("DecryptReader error: %v", err)
	}
	defer reader.Close()

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(out) != "hello" {
		t.Fatalf("unexpected plaintext: %s", string(out))
	}
}

func TestKryptografWithCompressionAdapters(t *testing.T) {
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey error: %v", err)
	}

	adapters := []struct {
		name   string
		option StreamOption
	}{
		{"gzip", WithGzip()},
		{"snappy", WithSnappy()},
		{"lz4", WithLZ4()},
	}

	payload := []byte("kryptograf compression")

	for _, tc := range adapters {
		kg := New(root).WithOptions(tc.option)
		mat, err := kg.MintDEK([]byte("cmp-" + tc.name))
		if err != nil {
			t.Fatalf("MintDEK error: %v", err)
		}

		var buf bytes.Buffer
		writer, err := kg.EncryptWriter(&buf, mat)
		if err != nil {
			t.Fatalf("EncryptWriter error: %v", err)
		}
		if _, err := writer.Write(payload); err != nil {
			t.Fatalf("Write error: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("Close error: %v", err)
		}

		reader, err := kg.DecryptReader(bytes.NewReader(buf.Bytes()), mat)
		if err != nil {
			t.Fatalf("DecryptReader error: %v", err)
		}
		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatalf("ReadAll error: %v", err)
		}
		if !bytes.Equal(data, payload) {
			t.Fatalf("%s: data mismatch", tc.name)
		}
	}
}

func TestKryptografWithAESGCMSIV(t *testing.T) {
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey error: %v", err)
	}
	kg := New(root)

	mat, err := kg.MintDEK([]byte("siv"))
	if err != nil {
		t.Fatalf("MintDEK error: %v", err)
	}

	var buf bytes.Buffer
	writer, err := kg.EncryptWriter(&buf, mat, WithCipher(cipher.AESGCMSIV()))
	if err != nil {
		t.Fatalf("EncryptWriter error: %v", err)
	}
	if _, err := writer.Write([]byte("hello")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	reader, err := kg.DecryptReader(bytes.NewReader(buf.Bytes()), mat, WithCipher(cipher.AESGCMSIV()))
	if err != nil {
		t.Fatalf("DecryptReader error: %v", err)
	}
	defer reader.Close()

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(out) != "hello" {
		t.Fatalf("unexpected plaintext: %s", string(out))
	}
}

func TestEnsureRootKey(t *testing.T) {
	var blob []byte
	store, err := keymgmt.LoadProtoInto([]byte(nil), &blob)
	if err != nil {
		t.Fatalf("LoadProtoInto error: %v", err)
	}

	root, err := store.EnsureRootKey()
	if err != nil {
		t.Fatalf("EnsureRootKey error: %v", err)
	}
	if root == (RootKey{}) {
		t.Fatalf("expected root key to be generated")
	}

	if err := store.Commit(); err != nil {
		t.Fatalf("Commit error after mint: %v", err)
	}
	if len(blob) == 0 {
		t.Fatalf("expected blob to contain data after commit")
	}

	prev := slices.Clone(blob)
	existing, err := store.EnsureRootKey()
	if err != nil {
		t.Fatalf("EnsureRootKey existing error: %v", err)
	}
	if existing != root {
		t.Fatalf("expected existing root to match original")
	}
	if err := store.Commit(); err != nil {
		t.Fatalf("Commit error without changes: %v", err)
	}
	if !bytes.Equal(blob, prev) {
		t.Fatalf("expected no additional write when root already present")
	}
}

func TestEnsureDescriptor(t *testing.T) {
	var blob []byte
	store, err := keymgmt.LoadProtoInto([]byte(nil), &blob)
	if err != nil {
		t.Fatalf("LoadProtoInto error: %v", err)
	}

	root, err := store.EnsureRootKey()
	if err != nil {
		t.Fatalf("EnsureRootKey error: %v", err)
	}
	if err := store.Commit(); err != nil {
		t.Fatalf("Commit root error: %v", err)
	}

	context := []byte("locker")
	mat1, err := store.EnsureDescriptor("LOCKD", root, context)
	if err != nil {
		t.Fatalf("EnsureDescriptor mint error: %v", err)
	}
	if mat1.Descriptor.NonceSize == 0 {
		t.Fatalf("expected descriptor nonce size to be set")
	}
	if err := store.Commit(); err != nil {
		t.Fatalf("Commit descriptor error: %v", err)
	}
	if len(blob) == 0 {
		t.Fatalf("expected blob to contain descriptor data")
	}

	prev := slices.Clone(blob)
	mat2, err := store.EnsureDescriptor("LOCKD", root, context)
	if err != nil {
		t.Fatalf("EnsureDescriptor existing error: %v", err)
	}
	if mat2.Descriptor != mat1.Descriptor {
		t.Fatalf("expected descriptor to match stored value")
	}
	if mat2.Key != mat1.Key {
		t.Fatalf("expected reconstructed DEK to match original")
	}
	if err := store.Commit(); err != nil {
		t.Fatalf("Commit without descriptor changes error: %v", err)
	}
	if !bytes.Equal(blob, prev) {
		t.Fatalf("expected no additional write when descriptor already present")
	}
}

func TestCertificateIDsFromPEM(t *testing.T) {
	certDER, pemData := generateTestCertificate(t)
	expected := sha256.Sum256(certDER)

	ids, err := CertificateIDsFromPEM(pemData)
	if err != nil {
		t.Fatalf("CertificateIDsFromPEM error: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(ids))
	}
	if ids[0] != hex.EncodeToString(expected[:]) {
		t.Fatalf("unexpected certificate ID: %s", ids[0])
	}

	idsReader, err := CertificateIDsFromReader(bytes.NewReader(pemData))
	if err != nil {
		t.Fatalf("CertificateIDsFromReader error: %v", err)
	}
	if len(idsReader) != 1 || idsReader[0] != ids[0] {
		t.Fatalf("reader IDs mismatch")
	}

	// Ensure non-certificate blocks are ignored.
	dataWithExtras := slices.Clone(pemData)
	dataWithExtras = append(dataWithExtras, []byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n")...)
	idsExtra, err := CertificateIDsFromPEM(dataWithExtras)
	if err != nil {
		t.Fatalf("CertificateIDsFromPEM with extras error: %v", err)
	}
	if len(idsExtra) != 1 || idsExtra[0] != ids[0] {
		t.Fatalf("expected extra data to be ignored")
	}
}

func TestCertificateIDsFromFile(t *testing.T) {
	_, pemData := generateTestCertificate(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	ids, err := CertificateIDsFromFile(path)
	if err != nil {
		t.Fatalf("CertificateIDsFromFile error: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(ids))
	}
}

func generateTestCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey error: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "kryptograf test",
			Organization: []string{"pkt.systems"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate error: %v", err)
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("pem.Encode error: %v", err)
	}
	return der, buf.Bytes()
}
