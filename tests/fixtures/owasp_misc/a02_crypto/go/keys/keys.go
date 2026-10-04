package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"time"
)

// codit-expect: CWE-321 fixed IV shared by every encryption
var fixedIV = []byte("abcdefghijklmnop")



func EncryptLegacy(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, fixedIV).CryptBlocks(out, plain)
	return out, nil
}

func EncryptDES(key, plain []byte) ([]byte, error) {
	// codit-expect: CWE-327 DES block cipher
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plain))
	block.Encrypt(out, plain)
	return out, nil
}

func Encrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// codit-safe: CWE-327 AES-GCM with a random nonce
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func LegacyKey() (*rsa.PrivateKey, error) {
	// codit-expect: CWE-326 1024-bit RSA key
	return rsa.GenerateKey(rand.Reader, 1024)
}



func SigningKey() (*rsa.PrivateKey, error) {
	// codit-safe: CWE-326 4096-bit RSA key
	return rsa.GenerateKey(rand.Reader, 4096)
}

func InternalClient() *http.Client {
	// codit-expect: CWE-295 certificate chain and hostname not verified
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}



func PartnerClient() (*http.Client, error) {
	pem, err := os.ReadFile("/etc/ssl/partner-ca.pem")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	// codit-safe: CWE-295 verification enabled against a pinned CA pool, TLS 1.2+
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}, nil
}
