package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"strings"
)

// rsaKeyBits is the size of every RSA key homepki generates.
const rsaKeyBits = 2048

// ecCurves maps a --key-type value to its elliptic curve.
var ecCurves = map[string]elliptic.Curve{
	"ecdsa":      elliptic.P256(),
	"ecdsa-p256": elliptic.P256(),
	"ecdsa-p384": elliptic.P384(),
	"ecdsa-p521": elliptic.P521(),
}

// ValidateKeyType rejects a --key-type value that GenerateKey would not accept,
// so a command can fail before it writes anything.
func ValidateKeyType(keyType string) error {
	kt := strings.ToLower(strings.TrimSpace(keyType))
	if kt == "" || kt == "rsa" || kt == "ed25519" {
		return nil
	}
	if _, ok := ecCurves[kt]; !ok {
		return fmt.Errorf("unknown key type %q (want one of: %s)", keyType, strings.Join(KeyTypes(), ", "))
	}
	return nil
}

// GenerateKey creates a private key for a --key-type value. An empty keyType
// means RSA-2048, the historical default.
func GenerateKey(keyType string) (crypto.Signer, error) {
	if err := ValidateKeyType(keyType); err != nil {
		return nil, err
	}
	kt := strings.ToLower(strings.TrimSpace(keyType))
	switch kt {
	case "", "rsa":
		return rsa.GenerateKey(rand.Reader, rsaKeyBits)
	case "ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	}
	return ecdsa.GenerateKey(ecCurves[kt], rand.Reader)
}

// KeyTypes lists the accepted --key-type values, sorted.
func KeyTypes() []string {
	types := []string{"rsa", "ed25519"}
	for k := range ecCurves {
		types = append(types, k)
	}
	sort.Strings(types)
	return types
}

// WriteKey writes a private key as an unencrypted PKCS#8 PEM file, mode 0600.
func WriteKey(path string, key crypto.Signer) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encoding private key: %w", err)
	}
	return writeSecret(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// LoadKey reads a PEM private key in PKCS#8, PKCS#1 (RSA) or SEC 1 (EC) form.
// PKCS#8 is what homepki writes; the other two cover keys made by hand.
func LoadKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("no private key PEM block found in %s", path)
		}
		switch block.Type {
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing %s: %w", path, err)
			}
			signer, ok := key.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("%s holds a %T key, which cannot sign", path, key)
			}
			return signer, nil
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(block.Bytes)
		}
	}
}

// writeSecret writes data with mode 0600, tightening the mode of an existing file.
func writeSecret(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
