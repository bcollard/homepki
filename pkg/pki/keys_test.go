package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	cases := []struct {
		keyType string
		curve   elliptic.Curve // nil means RSA-2048
	}{
		{"", nil},
		{"rsa", nil},
		{"RSA", nil},
		{"ecdsa", elliptic.P256()},
		{"ecdsa-p256", elliptic.P256()},
		{"ecdsa-p384", elliptic.P384()},
		{"ECDSA-P521", elliptic.P521()},
	}
	for _, c := range cases {
		key, err := GenerateKey(c.keyType)
		if err != nil {
			t.Errorf("GenerateKey(%q): unexpected error: %v", c.keyType, err)
			continue
		}
		switch k := key.(type) {
		case *rsa.PrivateKey:
			if c.curve != nil || k.N.BitLen() != rsaKeyBits {
				t.Errorf("GenerateKey(%q) = RSA-%d, want %v", c.keyType, k.N.BitLen(), c.curve)
			}
		case *ecdsa.PrivateKey:
			if k.Curve != c.curve {
				t.Errorf("GenerateKey(%q) = %s, want %v", c.keyType, k.Curve.Params().Name, c.curve)
			}
		default:
			t.Errorf("GenerateKey(%q) = %T", c.keyType, key)
		}
	}
}

func TestGenerateKeyRejectsUnknown(t *testing.T) {
	for _, bad := range []string{"ed25519", "ecdsa-p128", "rsa:4096", "ec"} {
		if _, err := GenerateKey(bad); err == nil {
			t.Errorf("GenerateKey(%q): expected error, got nil", bad)
		}
		if err := ValidateKeyType(bad); err == nil {
			t.Errorf("ValidateKeyType(%q): expected error, got nil", bad)
		}
	}
}

func TestWriteAndLoadKey(t *testing.T) {
	dir := t.TempDir()
	for _, kt := range []string{"rsa", "ecdsa-p384"} {
		key, err := GenerateKey(kt)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, kt+".key")
		if err := WriteKey(path, key); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("%s: mode %o, want 0600", kt, info.Mode().Perm())
		}
		loaded, err := LoadKey(path)
		if err != nil {
			t.Fatalf("LoadKey(%s): %v", kt, err)
		}
		if !publicKeysEqual(key.Public(), loaded.Public()) {
			t.Errorf("%s: loaded key does not match the written one", kt)
		}
	}
}

func TestLoadKeyLegacyFormats(t *testing.T) {
	dir := t.TempDir()

	rsaKey, err := GenerateKey("rsa")
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := GenerateKey("ecdsa")
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string]struct {
		block *pem.Block
		key   crypto.Signer
	}{
		"pkcs1": {&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey.(*rsa.PrivateKey))}, rsaKey},
		"sec1":  {&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}, ecKey},
	} {
		path := filepath.Join(dir, name+".key")
		// openssl writes "EC PARAMETERS" before a SEC 1 key; LoadKey must skip it.
		data := append(pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{0x06, 0x00}}), pem.EncodeToMemory(c.block)...)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadKey(path)
		if err != nil {
			t.Fatalf("LoadKey(%s): %v", name, err)
		}
		if !publicKeysEqual(c.key.Public(), loaded.Public()) {
			t.Errorf("%s: loaded key does not match", name)
		}
	}
}

func TestLoadKeyErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cases := map[string]string{
		"missing":   filepath.Join(dir, "missing.key"),
		"not PEM":   write("garbage.key", []byte("not a key")),
		"cert only": write("cert.key", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})),
		"bad PKCS8": write("bad8.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})),
	}
	for name, path := range cases {
		if _, err := LoadKey(path); err == nil {
			t.Errorf("LoadKey(%s): expected an error", name)
		}
	}
}

func TestWriteKeyTightensMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.key")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	key, err := GenerateKey("ecdsa")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteKey(path, key); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0600 {
		t.Errorf("mode %o after overwriting a 0644 file, want 0600", info.Mode().Perm())
	}
}
