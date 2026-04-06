package pki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CreateDirectory creates a directory if it doesn't exist.
func CreateDirectory(path string) error {
	return os.MkdirAll(path, 0755)
}

// CreatePrivateDirectory creates a private directory with restricted permissions.
func CreatePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}

// WriteFile writes content to a file.
func WriteFile(path string, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

// RunCommand executes a shell command.
func RunCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("Running: %s %s\n", name, strings.Join(args, " "))
	return cmd.Run()
}

// GenerateDefaultsConf generates the defaults.conf file.
func GenerateDefaultsConf(workDir, rootCALiteralName string) error {
	content := `### Defaults
default_bits            = 2048                  # RSA key size
encrypt_key             = yes                   # Protect private key
utf8                    = yes                   # Input is UTF-8
string_mask             = utf8only              # Emit UTF-8 strings
prompt                  = no                    # Don't prompt for DN
cert_opt                = no_header
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always,issuer:always
`
	filename := fmt.Sprintf("%s-defaults.conf", rootCALiteralName)
	return WriteFile(filepath.Join(workDir, filename), content)
}

// GetRootCALiteralName converts a domain name to a literal name (e.g., runlocal.dev -> runlocal-dev).
func GetRootCALiteralName(domain string) string {
	return strings.ReplaceAll(domain, ".", "-")
}

// ReadFile reads the content of a file.
func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// CleanPEMFile keeps only the PEM blocks in a file, removing any text outside.
func CleanPEMFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	inBlock := false

	for _, line := range lines {
		if strings.Contains(line, "-----BEGIN CERTIFICATE-----") {
			inBlock = true
		}
		if inBlock {
			newLines = append(newLines, line)
		}
		if strings.Contains(line, "-----END CERTIFICATE-----") {
			inBlock = false
		}
	}

	return os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0644)
}

// DirectoryExists checks if a directory exists.
func DirectoryExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return info.IsDir(), nil
}

// FileExists checks if a file exists.
func FileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return !info.IsDir(), nil
}

// ListDirectories lists subdirectories in a given path.
func ListDirectories(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, entry.Name())
		}
	}
	return dirs, nil
}

// GetCertExpiry parses a PEM certificate file and returns its expiry time and days remaining.
func GetCertExpiry(certPath string) (time.Time, int, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return time.Time{}, 0, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, 0, fmt.Errorf("failed to decode PEM in %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, 0, err
	}
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	return cert.NotAfter, daysLeft, nil
}

// VerifyRootCert verifies that the root CA cert at rootCACertPath is a valid self-signed certificate.
func VerifyRootCert(rootCACertPath string) error {
	data, err := os.ReadFile(rootCACertPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("failed to decode PEM in %s", rootCACertPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("root CA cert: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

// VerifyIntermediateCert verifies that the intermediate CA cert at intermediateCertPath
// was signed by the root CA at rootCACertPath.
func VerifyIntermediateCert(intermediateCertPath, rootCACertPath string) error {
	loadCert := func(path string) (*x509.Certificate, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM in %s", path)
		}
		return x509.ParseCertificate(block.Bytes)
	}

	intermediateCert, err := loadCert(intermediateCertPath)
	if err != nil {
		return fmt.Errorf("intermediate cert: %w", err)
	}
	rootCACert, err := loadCert(rootCACertPath)
	if err != nil {
		return fmt.Errorf("root CA cert: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCACert)

	_, err = intermediateCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

// VerifyLeafCert verifies that the leaf cert at leafCertPath was signed by the
// intermediate CA at intermediateCertPath, which in turn was signed by the root
// CA at rootCACertPath. keyUsages specifies the expected extended key usages
// (e.g. x509.ExtKeyUsageServerAuth or x509.ExtKeyUsageClientAuth).
func VerifyLeafCert(leafCertPath, intermediateCertPath, rootCACertPath string, keyUsages []x509.ExtKeyUsage) error {
	loadCert := func(path string) (*x509.Certificate, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM in %s", path)
		}
		return x509.ParseCertificate(block.Bytes)
	}

	leafCert, err := loadCert(leafCertPath)
	if err != nil {
		return fmt.Errorf("leaf cert: %w", err)
	}
	intermediateCert, err := loadCert(intermediateCertPath)
	if err != nil {
		return fmt.Errorf("intermediate cert: %w", err)
	}
	rootCACert, err := loadCert(rootCACertPath)
	if err != nil {
		return fmt.Errorf("root CA cert: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCACert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCert)

	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     keyUsages,
	})
	return err
}

// ListFiles lists files with a specific extension in a given path.
func ListFiles(path string, ext string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ext) {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}
