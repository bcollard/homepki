package pki

import (
	"fmt"
	"sort"
	"strings"
)

// ecCurves maps a --key-type value to the OpenSSL curve name.
var ecCurves = map[string]string{
	"ecdsa":      "P-256",
	"ecdsa-p256": "P-256",
	"ecdsa-p384": "P-384",
	"ecdsa-p521": "P-521",
}

// KeyGenArgs returns the `openssl req` arguments that select the private key
// algorithm. An empty keyType means RSA-2048, the historical default.
func KeyGenArgs(keyType string) ([]string, error) {
	switch kt := strings.ToLower(strings.TrimSpace(keyType)); kt {
	case "", "rsa":
		return []string{"-newkey", "rsa:2048"}, nil
	default:
		curve, ok := ecCurves[kt]
		if !ok {
			return nil, fmt.Errorf("unknown key type %q (want one of: %s)", keyType, strings.Join(KeyTypes(), ", "))
		}
		return []string{
			"-newkey", "ec",
			"-pkeyopt", "ec_paramgen_curve:" + curve,
			"-pkeyopt", "ec_param_enc:named_curve",
		}, nil
	}
}

// KeyTypes lists the accepted --key-type values, sorted.
func KeyTypes() []string {
	types := []string{"rsa"}
	for k := range ecCurves {
		types = append(types, k)
	}
	sort.Strings(types)
	return types
}
