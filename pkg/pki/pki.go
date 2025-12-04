package pki

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
