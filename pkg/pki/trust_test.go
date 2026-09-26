package pki

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMacOSTrustArgs(t *testing.T) {
	cert := "/tmp/runlocal-dev-root-ca.crt"

	want := []string{"security", "add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain", cert}
	if got := MacOSTrustInstallArgs(cert); !reflect.DeepEqual(got, want) {
		t.Errorf("install args = %v, want %v", got, want)
	}

	want = []string{"security", "remove-trusted-cert", "-d", cert}
	if got := MacOSTrustUninstallArgs(cert); !reflect.DeepEqual(got, want) {
		t.Errorf("uninstall args = %v, want %v", got, want)
	}

	want = []string{"security", "verify-cert", "-c", cert}
	if got := MacOSTrustStatusArgs(cert); !reflect.DeepEqual(got, want) {
		t.Errorf("status args = %v, want %v", got, want)
	}
}

func TestWithSudo(t *testing.T) {
	argv := []string{"security", "add-trusted-cert"}

	got := withSudo(argv, 0)
	if !reflect.DeepEqual(got, argv) {
		t.Errorf("as root: %v, want the command unchanged", got)
	}

	got = withSudo(argv, 501)
	want := []string{"sudo", "security", "add-trusted-cert"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("as non-root: %v, want %v", got, want)
	}

	// The input slice must not be aliased into the result.
	if argv[0] != "security" {
		t.Errorf("withSudo mutated its argument: %v", argv)
	}
}

func TestLinuxStoreCommands(t *testing.T) {
	s := LinuxStore{AnchorDir: "/usr/local/share/ca-certificates", Update: []string{"update-ca-certificates"}}
	anchor := "/usr/local/share/ca-certificates/homepki-runlocal-dev.crt"
	if got := s.AnchorPath("runlocal-dev"); got != anchor {
		t.Errorf("AnchorPath = %q", got)
	}
	want := [][]string{{"install", "-m", "0644", "/w/root.crt", anchor}, {"update-ca-certificates"}}
	if got := s.InstallCommands("/w/root.crt", "runlocal-dev"); !reflect.DeepEqual(got, want) {
		t.Errorf("InstallCommands = %v", got)
	}
	want = [][]string{{"rm", "-f", anchor}, {"update-ca-certificates"}}
	if got := s.UninstallCommands("runlocal-dev"); !reflect.DeepEqual(got, want) {
		t.Errorf("UninstallCommands = %v", got)
	}
}

func TestNSSDatabases(t *testing.T) {
	home := t.TempDir()
	mk := func(rel, file string) string {
		dir := filepath.Join(home, rel)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if file != "" {
			os.WriteFile(filepath.Join(dir, file), nil, 0644)
		}
		return dir
	}
	ff := mk("Library/Application Support/Firefox/Profiles/abc.default-release", "cert9.db")
	old := mk(".mozilla/firefox/old.default", "cert8.db")
	mk(".mozilla/firefox/empty.default", "")
	chrome := mk(".pki/nssdb", "cert9.db")

	got := NSSDatabases(home)
	want := []string{"sql:" + ff, "dbm:" + old, "sql:" + chrome}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NSSDatabases = %v, want %v", got, want)
	}
	if got := NSSDatabases(t.TempDir()); len(got) != 0 {
		t.Errorf("empty home: %v", got)
	}
}

// TestNSSRoundTrip drives a real certutil against a scratch database.
func TestNSSRoundTrip(t *testing.T) {
	certutil, err := FindCertutil()
	if err != nil {
		t.Skip("certutil not installed")
	}
	dir := t.TempDir()
	db := "sql:" + dir
	if out, err := RunQuiet([]string{certutil, "-N", "-d", db, "--empty-password"}); err != nil {
		t.Fatalf("creating NSS db: %v\n%s", err, out)
	}
	c := newTestChain(t, "ecdsa", NameConstraints{}, NameConstraints{})
	cert := filepath.Join(dir, "root.crt")
	WriteCerts(cert, c.root)
	nick := NSSNickname("test-local")

	if _, err := RunQuiet(NSSStatusArgs(certutil, db, nick)); err == nil {
		t.Fatal("status before install: trusted")
	}
	if out, err := RunQuiet(NSSInstallArgs(certutil, db, nick, cert)); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if out, err := RunQuiet(NSSStatusArgs(certutil, db, nick)); err != nil {
		t.Fatalf("status after install: %v\n%s", err, out)
	}
	if out, err := RunQuiet(NSSUninstallArgs(certutil, db, nick)); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	if _, err := RunQuiet(NSSStatusArgs(certutil, db, nick)); err == nil {
		t.Fatal("status after uninstall: trusted")
	}
}

func TestJavaTrustStore(t *testing.T) {
	if _, _, err := JavaTrustStore(""); err == nil {
		t.Error("empty JAVA_HOME accepted")
	}
	for _, rel := range []string{"lib/security/cacerts", "jre/lib/security/cacerts"} {
		home := t.TempDir()
		os.MkdirAll(filepath.Join(home, "bin"), 0755)
		os.WriteFile(filepath.Join(home, "bin", "keytool"), nil, 0755)
		if _, _, err := JavaTrustStore(home); err == nil {
			t.Error("JDK without cacerts accepted")
		}
		os.MkdirAll(filepath.Dir(filepath.Join(home, rel)), 0755)
		os.WriteFile(filepath.Join(home, rel), nil, 0644)
		cacerts, keytool, err := JavaTrustStore(home)
		if err != nil || cacerts != filepath.Join(home, rel) || keytool != filepath.Join(home, "bin", "keytool") {
			t.Errorf("%s: %q %q %v", rel, cacerts, keytool, err)
		}
		if !IsWritable(cacerts) {
			t.Error("IsWritable on a file we own: false")
		}
	}
	if IsWritable(filepath.Join(t.TempDir(), "missing")) {
		t.Error("IsWritable on a missing file: true")
	}

	want := []string{"kt", "-importcert", "-noprompt", "-trustcacerts", "-keystore", "ca", "-storepass", "changeit", "-alias", "homepki-x", "-file", "r.crt"}
	if got := JavaInstallArgs("kt", "ca", JavaAlias("x"), "r.crt"); !reflect.DeepEqual(got, want) {
		t.Errorf("JavaInstallArgs = %v", got)
	}
}
