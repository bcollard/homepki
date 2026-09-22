package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/bcollard/homepki/pkg/pki"
)

// rootCAPaths resolves the working directory and the root CA certificate for a domain.
func rootCAPaths(domain string) (workDir string, certPath string, err error) {
	baseDir, err := getEffectiveWorkDir()
	if err != nil {
		return "", "", err
	}
	literal := pki.GetRootCALiteralName(domain)
	workDir = filepath.Join(baseDir, literal)
	certPath = filepath.Join(workDir, "ca", fmt.Sprintf("%s-root-ca.crt", literal))
	return workDir, certPath, nil
}
