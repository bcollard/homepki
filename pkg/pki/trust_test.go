package pki

import (
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
