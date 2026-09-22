package pki

import (
	"reflect"
	"testing"
)

func TestKeyGenArgs(t *testing.T) {
	cases := []struct {
		keyType string
		want    []string
	}{
		{"", []string{"-newkey", "rsa:2048"}},
		{"rsa", []string{"-newkey", "rsa:2048"}},
		{"RSA", []string{"-newkey", "rsa:2048"}},
		{"ecdsa", []string{"-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-pkeyopt", "ec_param_enc:named_curve"}},
		{"ecdsa-p256", []string{"-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-pkeyopt", "ec_param_enc:named_curve"}},
		{"ecdsa-p384", []string{"-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384", "-pkeyopt", "ec_param_enc:named_curve"}},
		{"ECDSA-P521", []string{"-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-521", "-pkeyopt", "ec_param_enc:named_curve"}},
	}
	for _, c := range cases {
		got, err := KeyGenArgs(c.keyType)
		if err != nil {
			t.Errorf("KeyGenArgs(%q): unexpected error: %v", c.keyType, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("KeyGenArgs(%q) = %v, want %v", c.keyType, got, c.want)
		}
	}
}

func TestKeyGenArgsRejectsUnknown(t *testing.T) {
	for _, bad := range []string{"ed25519", "ecdsa-p128", "rsa:4096", "ec"} {
		if _, err := KeyGenArgs(bad); err == nil {
			t.Errorf("KeyGenArgs(%q): expected error, got nil", bad)
		}
	}
}
