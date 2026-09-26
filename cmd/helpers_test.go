package cmd

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/bcollard/homepki/pkg/pki"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// resetFlags puts every flag of cmd and its subcommands back to its default.
// The commands share package-level flag variables and cobra keeps flag state
// between Execute calls, so each test run starts from a clean slate.
func resetFlags(cmd *cobra.Command) {
	reset := func(f *pflag.Flag) {
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			_ = sv.Replace(nil)
		} else {
			_ = f.Value.Set(f.DefValue)
		}
		f.Changed = false
	}
	cmd.Flags().VisitAll(reset)
	cmd.PersistentFlags().VisitAll(reset)
	for _, c := range cmd.Commands() {
		resetFlags(c)
	}
}

// execute runs homepki with args and returns what it printed on stdout.
func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetFlags(rootCmd)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() {
		out, _ := io.ReadAll(r)
		done <- out
	}()

	var stderr bytes.Buffer
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs(args)
	runErr := rootCmd.Execute()

	w.Close()
	os.Stdout = stdout
	return string(<-done), runErr
}

// pkiEnv runs homepki commands against a private workdir.
type pkiEnv struct {
	t   *testing.T
	dir string
}

func newPKIEnv(t *testing.T) *pkiEnv {
	t.Setenv("HOMEPKI_WORKDIR", "")
	return &pkiEnv{t: t, dir: t.TempDir()}
}

func (e *pkiEnv) run(args ...string) (string, error) {
	e.t.Helper()
	return execute(e.t, append(args, "--workdir", e.dir)...)
}

func (e *pkiEnv) mustRun(args ...string) string {
	e.t.Helper()
	out, err := e.run(args...)
	if err != nil {
		e.t.Fatalf("homepki %v: %v\n%s", args, err, out)
	}
	return out
}

func (e *pkiEnv) path(parts ...string) string {
	return filepath.Join(append([]string{e.dir}, parts...)...)
}

func (e *pkiEnv) cert(parts ...string) *x509.Certificate {
	e.t.Helper()
	c, err := pki.LoadCert(e.path(parts...))
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *pkiEnv) key(parts ...string) crypto.Signer {
	e.t.Helper()
	k, err := pki.LoadKey(e.path(parts...))
	if err != nil {
		e.t.Fatal(err)
	}
	return k
}

// hierarchy creates a root CA for domain and an intermediate named bu1.
func (e *pkiEnv) hierarchy(domain string, extra ...string) {
	e.t.Helper()
	e.mustRun(append([]string{"root-ca", "-d", domain}, extra...)...)
	e.mustRun("intermediate-ca", "-d", domain, "-n", "bu1")
}

type listEntry struct {
	Name       string `json:"name"`
	Expires    string `json:"expires"`
	DaysLeft   int    `json:"days_left"`
	ChainValid bool   `json:"chain_valid"`
	ChainError string `json:"chain_error"`
}

func (e *pkiEnv) list(args ...string) []listEntry {
	e.t.Helper()
	out := e.mustRun(append(args, "-o", "json")...)
	var entries []listEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		e.t.Fatalf("list %v: %v\n%s", args, err, out)
	}
	return entries
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

// writeCSR writes a CSR for subject and dnsNames. It also asks for
// basicConstraints CA:TRUE, which sign must ignore.
func writeCSR(t *testing.T, subject pkix.Name, dnsNames ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTrue, err := asn1.Marshal(struct {
		IsCA bool `asn1:"optional"`
	}{true})
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         subject,
		DNSNames:        dnsNames,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: caTrue}},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "req.csr")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
