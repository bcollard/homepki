package pki

import (
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGetRootCALiteralName(t *testing.T) {
	cases := map[string]string{
		"runlocal.dev":        "runlocal-dev",
		"klimax.internal":     "klimax-internal",
		"a.b.c.example":       "a-b-c-example",
		"localhost":           "localhost",
		"already-dashed.test": "already-dashed-test",
	}
	for in, want := range cases {
		if got := GetRootCALiteralName(in); got != want {
			t.Errorf("GetRootCALiteralName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDirectoryAndFileHelpers(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "a", "b")
	if err := CreateDirectory(sub); err != nil {
		t.Fatal(err)
	}
	priv := filepath.Join(dir, "private")
	if err := CreatePrivateDirectory(priv); err != nil {
		t.Fatal(err)
	}
	// A second call on an existing, looser directory tightens it.
	if err := os.Chmod(priv, 0755); err != nil {
		t.Fatal(err)
	}
	if err := CreatePrivateDirectory(priv); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(priv); err != nil || info.Mode().Perm() != 0700 {
		t.Errorf("private directory mode = %v (%v), want 0700", info.Mode().Perm(), err)
	}

	file := filepath.Join(dir, "x.crt")
	if err := WriteFile(file, "content"); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(filepath.Join(dir, "y.key"), "k"); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		path          string
		isDir, isFile bool
	}{
		{sub, true, false},
		{file, false, true},
		{filepath.Join(dir, "missing"), false, false},
	} {
		if got, err := DirectoryExists(c.path); err != nil || got != c.isDir {
			t.Errorf("DirectoryExists(%s) = %v, %v; want %v", c.path, got, err, c.isDir)
		}
		if got, err := FileExists(c.path); err != nil || got != c.isFile {
			t.Errorf("FileExists(%s) = %v, %v; want %v", c.path, got, err, c.isFile)
		}
	}

	dirs, err := ListDirectories(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a", "private"}; !reflect.DeepEqual(dirs, want) {
		t.Errorf("ListDirectories = %v, want %v", dirs, want)
	}
	files, err := ListFiles(dir, ".crt")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"x.crt"}; !reflect.DeepEqual(files, want) {
		t.Errorf("ListFiles = %v, want %v", files, want)
	}
	if _, err := ListDirectories(filepath.Join(dir, "missing")); err == nil {
		t.Error("ListDirectories on a missing directory: expected an error")
	}
	if _, err := ListFiles(filepath.Join(dir, "missing"), ".crt"); err == nil {
		t.Error("ListFiles on a missing directory: expected an error")
	}
}

// writeChain writes a chain from newTestChain to disk and returns the paths of
// the root, intermediate, and a server leaf.
func writeChain(t *testing.T, c testChain) (root, intermediate, leaf string) {
	t.Helper()
	dir := t.TempDir()
	root = filepath.Join(dir, "root.crt")
	intermediate = filepath.Join(dir, "intermediate.crt")
	leaf = filepath.Join(dir, "leaf.crt")
	if err := WriteCerts(root, c.root); err != nil {
		t.Fatal(err)
	}
	if err := WriteCerts(intermediate, c.intermediate); err != nil {
		t.Fatal(err)
	}
	if err := WriteCerts(leaf, c.leaf(t, "rsa", ServerLeaf, "gw.bu1.test.local")); err != nil {
		t.Fatal(err)
	}
	return root, intermediate, leaf
}

func TestVerifyCertFiles(t *testing.T) {
	c := newTestChain(t, "ecdsa", NameConstraints{}, NameConstraints{})
	root, intermediate, leaf := writeChain(t, c)
	other := newTestChain(t, "ecdsa", NameConstraints{}, NameConstraints{})
	otherRoot, otherIntermediate, _ := writeChain(t, other)
	missing := filepath.Join(t.TempDir(), "missing.crt")
	server := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	if err := VerifyRootCert(root); err != nil {
		t.Errorf("VerifyRootCert: %v", err)
	}
	if err := VerifyRootCert(intermediate); err == nil {
		t.Error("VerifyRootCert accepted an intermediate as a self-signed root")
	}
	if err := VerifyRootCert(missing); err == nil {
		t.Error("VerifyRootCert accepted a missing file")
	}

	if err := VerifyIntermediateCert(intermediate, root); err != nil {
		t.Errorf("VerifyIntermediateCert: %v", err)
	}
	if err := VerifyIntermediateCert(intermediate, otherRoot); err == nil {
		t.Error("VerifyIntermediateCert accepted a foreign root")
	}
	if err := VerifyIntermediateCert(missing, root); err == nil || !strings.Contains(err.Error(), "intermediate cert") {
		t.Errorf("VerifyIntermediateCert(missing intermediate) = %v", err)
	}
	if err := VerifyIntermediateCert(intermediate, missing); err == nil || !strings.Contains(err.Error(), "root CA cert") {
		t.Errorf("VerifyIntermediateCert(missing root) = %v", err)
	}

	if err := VerifyLeafCert(leaf, intermediate, root, server); err != nil {
		t.Errorf("VerifyLeafCert: %v", err)
	}
	if err := VerifyLeafCert(leaf, otherIntermediate, otherRoot, server); err == nil {
		t.Error("VerifyLeafCert accepted a foreign chain")
	}
	if err := VerifyLeafCert(leaf, intermediate, root, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}); err == nil {
		t.Error("VerifyLeafCert accepted a server leaf as a client certificate")
	}
	for _, paths := range [][3]string{{missing, intermediate, root}, {leaf, missing, root}, {leaf, intermediate, missing}} {
		if err := VerifyLeafCert(paths[0], paths[1], paths[2], server); err == nil {
			t.Errorf("VerifyLeafCert(%v): expected an error", paths)
		}
	}
}

func TestGetCertExpiry(t *testing.T) {
	c := newTestChain(t, "ecdsa", NameConstraints{}, NameConstraints{})
	root, _, leaf := writeChain(t, c)

	expiry, days, err := GetCertExpiry(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if days != LeafValidityDays-1 && days != LeafValidityDays {
		t.Errorf("leaf days left = %d, want about %d", days, LeafValidityDays)
	}
	if d := time.Until(expiry); d < time.Duration(LeafValidityDays-1)*24*time.Hour {
		t.Errorf("leaf expires in %v", d)
	}
	if _, days, _ := GetCertExpiry(root); days < CAValidityDays-1 {
		t.Errorf("root days left = %d, want about %d", days, CAValidityDays)
	}
	if _, _, err := GetCertExpiry(filepath.Join(t.TempDir(), "missing.crt")); err == nil {
		t.Error("GetCertExpiry on a missing file: expected an error")
	}
}

func TestSANsFromCSR(t *testing.T) {
	csr, err := LoadCSR(writeCSR(t, matchingSubject(), []string{"gw.bu1.runlocal.dev", "gw.local"}))
	if err != nil {
		t.Fatal(err)
	}
	sans := SANsFromCSR(csr)
	if !reflect.DeepEqual(sans.DNS, []string{"gw.bu1.runlocal.dev", "gw.local"}) || sans.Count() != 2 {
		t.Errorf("SANsFromCSR = %+v", sans)
	}

	csr.IPAddresses = []net.IP{net.ParseIP("10.0.0.1")}
	csr.EmailAddresses = []string{"ops@runlocal.dev"}
	if got := SANsFromCSR(csr).Count(); got != 4 {
		t.Errorf("Count() = %d, want 4", got)
	}
}
