package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bcollard/homepki/pkg/pki"
)

// forceGenerate backs the --force flag shared by every generate command.
var forceGenerate bool

// pathsPresent returns the subset of paths that exist on disk.
func pathsPresent(paths ...string) []string {
	var present []string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			present = append(present, p)
		}
	}
	return present
}

// replaceLeaf clears an existing leaf so that it can be issued again: the files
// on disk, and the row in the intermediate's CA database that would otherwise
// make openssl refuse a second certificate for the same subject.
func replaceLeaf(intermediateCADir, commonName string, files []string) error {
	for _, f := range files {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	removed, err := pki.RemoveIndexEntry(filepath.Join(intermediateCADir, "db", "index.db"), commonName)
	if err != nil {
		return err
	}
	fmt.Printf("--force: replacing %s (removed %d file(s), %d CA database row(s))\n", commonName, len(files), removed)
	return nil
}

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
