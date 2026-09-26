package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
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
