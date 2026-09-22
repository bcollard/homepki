package pki

import (
	"os"
	"os/exec"
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
