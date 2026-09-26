package pki

import (
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// systemKeychain is the macOS keychain holding machine-wide trust settings.
const systemKeychain = "/Library/Keychains/System.keychain"

// IsMacOS reports whether trust-store management is available on this host.
func IsMacOS() bool {
	return runtime.GOOS == "darwin"
}

// MacOSTrustInstallArgs builds the command that adds a root CA certificate to
// the machine-wide trust store. It needs root, so it is normally run under sudo.
func MacOSTrustInstallArgs(certPath string) []string {
	return []string{"security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", systemKeychain, certPath}
}

// MacOSTrustUninstallArgs builds the command that removes a root CA certificate
// from the machine-wide trust store.
func MacOSTrustUninstallArgs(certPath string) []string {
	return []string{"security", "remove-trusted-cert", "-d", certPath}
}

// MacOSTrustStatusArgs builds the command that evaluates a certificate against
// the current trust settings. It exits non-zero when the certificate is not
// trusted, and needs no privileges.
func MacOSTrustStatusArgs(certPath string) []string {
	return []string{"security", "verify-cert", "-c", certPath}
}

// LinuxStore is a distribution's system trust store: a directory of anchor
// certificates and the command that rebuilds the bundle from it.
type LinuxStore struct {
	AnchorDir string
	Update    []string
}

// linuxStores lists the anchor directories homepki knows, in the order it
// probes them. The first that exists wins.
var linuxStores = []LinuxStore{
	{"/etc/pki/ca-trust/source/anchors", []string{"update-ca-trust", "extract"}},       // Fedora, RHEL, CentOS
	{"/usr/local/share/ca-certificates", []string{"update-ca-certificates"}},           // Debian, Ubuntu, Alpine
	{"/etc/ca-certificates/trust-source/anchors", []string{"trust", "extract-compat"}}, // Arch
	{"/usr/share/pki/trust/anchors", []string{"update-ca-certificates"}},               // openSUSE
}

// DetectLinuxStore returns the system trust store of this Linux host.
func DetectLinuxStore() (LinuxStore, bool) {
	if runtime.GOOS != "linux" {
		return LinuxStore{}, false
	}
	for _, s := range linuxStores {
		if info, err := os.Stat(s.AnchorDir); err == nil && info.IsDir() {
			return s, true
		}
	}
	return LinuxStore{}, false
}

// AnchorPath is where a root CA is copied in the store. The .crt extension is
// required by update-ca-certificates.
func (s LinuxStore) AnchorPath(literal string) string {
	return filepath.Join(s.AnchorDir, "homepki-"+literal+".crt")
}

// InstallCommands copies the certificate into the anchor directory and
// rebuilds the bundle. Both need root.
func (s LinuxStore) InstallCommands(certPath, literal string) [][]string {
	return [][]string{
		{"install", "-m", "0644", certPath, s.AnchorPath(literal)},
		s.Update,
	}
}

// UninstallCommands removes the anchor and rebuilds the bundle.
func (s LinuxStore) UninstallCommands(literal string) [][]string {
	return [][]string{
		{"rm", "-f", s.AnchorPath(literal)},
		s.Update,
	}
}

// linuxBundles lists the CA bundles distributions build from their anchors,
// the same files crypto/x509 reads.
var linuxBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian, Ubuntu, Arch, Gentoo
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora, RHEL
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS, RHEL 7
	"/etc/ssl/ca-bundle.pem",                            // openSUSE
	"/etc/ssl/cert.pem",                                 // Alpine
}

// SystemTrusts reports whether the platform's trust store accepts cert as a
// root. On Linux the bundle files are read on every call:
// x509.SystemCertPool caches them for the life of the process, so it would
// miss a root installed after the first check.
func SystemTrusts(cert *x509.Certificate) error {
	pool, err := x509.SystemCertPool()
	if runtime.GOOS == "linux" {
		pool, err = x509.NewCertPool(), nil
		bundles := linuxBundles
		if f := os.Getenv("SSL_CERT_FILE"); f != "" {
			bundles = []string{f}
		}
		for _, b := range bundles {
			if data, readErr := os.ReadFile(b); readErr == nil {
				pool.AppendCertsFromPEM(data)
			}
		}
	}
	if err != nil {
		return err
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err
}

// NSSNickname names a root CA inside an NSS database.
func NSSNickname(literal string) string {
	return "homepki " + literal + " root CA"
}

// nssProfileGlobs lists where Firefox profiles and the Chrome/Chromium NSS
// database live, relative to the home directory.
var nssProfileGlobs = []string{
	"Library/Application Support/Firefox/Profiles/*",  // Firefox, macOS
	".mozilla/firefox/*",                              // Firefox, Linux
	"snap/firefox/common/.mozilla/firefox/*",          // Firefox, Ubuntu snap
	".var/app/org.mozilla.firefox/.mozilla/firefox/*", // Firefox, Flatpak
	".pki/nssdb",                       // Chrome and Chromium, Linux
	"snap/chromium/current/.pki/nssdb", // Chromium, Ubuntu snap
}

// NSSDatabases returns the NSS databases under home, in certutil's -d form:
// sql:DIR for cert9.db, dbm:DIR for the legacy cert8.db.
func NSSDatabases(home string) []string {
	var dbs []string
	for _, g := range nssProfileGlobs {
		matches, _ := filepath.Glob(filepath.Join(home, g))
		for _, dir := range matches {
			if _, err := os.Stat(filepath.Join(dir, "cert9.db")); err == nil {
				dbs = append(dbs, "sql:"+dir)
			} else if _, err := os.Stat(filepath.Join(dir, "cert8.db")); err == nil {
				dbs = append(dbs, "dbm:"+dir)
			}
		}
	}
	return dbs
}

// FindCertutil locates NSS's certutil. Homebrew's nss formula is keg-only on
// some setups, so its prefix is checked when certutil is not on PATH.
func FindCertutil() (string, error) {
	if p, err := exec.LookPath("certutil"); err == nil {
		return p, nil
	}
	for _, p := range []string{"/opt/homebrew/opt/nss/bin/certutil", "/usr/local/opt/nss/bin/certutil"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("certutil not found")
}

// NSSInstallArgs adds a root CA to an NSS database, trusted for TLS servers.
func NSSInstallArgs(certutil, db, nickname, certPath string) []string {
	return []string{certutil, "-A", "-d", db, "-t", "C,,", "-n", nickname, "-i", certPath}
}

// NSSUninstallArgs deletes a root CA from an NSS database.
func NSSUninstallArgs(certutil, db, nickname string) []string {
	return []string{certutil, "-D", "-d", db, "-n", nickname}
}

// NSSStatusArgs verifies a root CA in an NSS database as a TLS CA. It exits
// non-zero when the certificate is missing or not trusted.
func NSSStatusArgs(certutil, db, nickname string) []string {
	return []string{certutil, "-V", "-d", db, "-u", "L", "-n", nickname}
}

// JavaStorePassword is the password every JDK ships its cacerts with.
const JavaStorePassword = "changeit"

// JavaAlias names a root CA inside a Java keystore. keytool lowercases
// aliases, so the literal name is used as is.
func JavaAlias(literal string) string {
	return "homepki-" + literal
}

// JavaTrustStore locates the cacerts keystore and keytool of the JDK at
// javaHome: lib/security for JDK 9 and later, jre/lib/security for JDK 8.
func JavaTrustStore(javaHome string) (cacerts, keytool string, err error) {
	if javaHome == "" {
		return "", "", fmt.Errorf("JAVA_HOME is not set")
	}
	keytool = filepath.Join(javaHome, "bin", "keytool")
	if _, err := os.Stat(keytool); err != nil {
		return "", "", fmt.Errorf("no keytool at %s", keytool)
	}
	for _, rel := range []string{"lib/security/cacerts", "jre/lib/security/cacerts"} {
		p := filepath.Join(javaHome, rel)
		if _, err := os.Stat(p); err == nil {
			return p, keytool, nil
		}
	}
	return "", "", fmt.Errorf("no cacerts keystore under %s", javaHome)
}

// JavaInstallArgs imports a root CA into a keystore as a trusted certificate.
func JavaInstallArgs(keytool, cacerts, alias, certPath string) []string {
	return []string{keytool, "-importcert", "-noprompt", "-trustcacerts", "-keystore", cacerts,
		"-storepass", JavaStorePassword, "-alias", alias, "-file", certPath}
}

// JavaUninstallArgs deletes a root CA from a keystore.
func JavaUninstallArgs(keytool, cacerts, alias string) []string {
	return []string{keytool, "-delete", "-keystore", cacerts, "-storepass", JavaStorePassword, "-alias", alias}
}

// JavaStatusArgs lists one alias of a keystore. It exits non-zero when the
// alias is absent.
func JavaStatusArgs(keytool, cacerts, alias string) []string {
	return []string{keytool, "-list", "-keystore", cacerts, "-storepass", JavaStorePassword, "-alias", alias}
}

// IsWritable reports whether the current user can write path, so root is only
// asked for when needed.
func IsWritable(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// Sudo prefixes a command with sudo unless the process already runs as root.
func Sudo(argv []string) []string {
	return withSudo(argv, os.Geteuid())
}

func withSudo(argv []string, euid int) []string {
	if euid == 0 {
		return argv
	}
	return append([]string{"sudo"}, argv...)
}

// RunInteractive runs a command with the process stdio attached, so sudo can
// prompt for a password.
func RunInteractive(argv []string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// RunQuiet runs a command and returns its combined output instead of printing it.
func RunQuiet(argv []string) (string, error) {
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
