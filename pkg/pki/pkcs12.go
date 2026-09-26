package pki

import (
	"crypto"
	"crypto/x509"
	"fmt"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// DefaultPKCS12Password is the password mkcert and the Java keystore default
// to, so existing tooling opens the file without extra flags.
const DefaultPKCS12Password = pkcs12.DefaultPassword

// WritePKCS12 bundles a private key, its certificate and the CA chain into a
// PKCS#12 file, mode 0600. It uses the 3DES/SHA-1 legacy encoding: the one
// that Java, macOS Keychain, Windows and OpenSSL 3 all import without extra
// options.
func WritePKCS12(path string, key crypto.Signer, cert *x509.Certificate, chain []*x509.Certificate, password string) error {
	data, err := pkcs12.LegacyDES.Encode(key, cert, chain, password)
	if err != nil {
		return fmt.Errorf("encoding PKCS#12: %w", err)
	}
	return writeSecret(path, data)
}
