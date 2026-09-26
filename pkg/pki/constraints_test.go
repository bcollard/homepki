package pki

import (
	"crypto/x509"
	"fmt"
	"reflect"
	"testing"
)

func TestParseNameConstraints(t *testing.T) {
	nc, err := ParseNameConstraints([]string{
		"permitted;DNS:.klimax.internal",
		"DNS:klimax.test",
		"Excluded;dns:bad.klimax.internal",
		"permitted;IP:10.1.2.3/8",
		"permitted;IP:192.168.0.0/255.255.0.0",
		"excluded;IP:fd00::/8",
		"permitted;email:.klimax.internal",
		"excluded;URI:evil.klimax.internal",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []string{".klimax.internal", "klimax.test"}; !reflect.DeepEqual(nc.PermittedDNS, want) {
		t.Errorf("PermittedDNS = %q, want %q", nc.PermittedDNS, want)
	}
	if want := []string{"bad.klimax.internal"}; !reflect.DeepEqual(nc.ExcludedDNS, want) {
		t.Errorf("ExcludedDNS = %q, want %q", nc.ExcludedDNS, want)
	}
	var ips []string
	for _, n := range nc.PermittedIPs {
		ips = append(ips, n.String())
	}
	if want := []string{"10.0.0.0/8", "192.168.0.0/16"}; !reflect.DeepEqual(ips, want) {
		t.Errorf("PermittedIPs = %q, want %q", ips, want)
	}
	if len(nc.ExcludedIPs) != 1 || nc.ExcludedIPs[0].String() != "fd00::/8" {
		t.Errorf("ExcludedIPs = %v, want [fd00::/8]", nc.ExcludedIPs)
	}
	if len(nc.PermittedIPs[0].IP) != 4 {
		t.Errorf("IPv4 range stored as %d bytes, want 4", len(nc.PermittedIPs[0].IP))
	}
	if !reflect.DeepEqual(nc.PermittedEmails, []string{".klimax.internal"}) || !reflect.DeepEqual(nc.ExcludedURIs, []string{"evil.klimax.internal"}) {
		t.Errorf("email/URI subtrees not parsed: %+v", nc)
	}
	if nc.Empty() {
		t.Error("Empty() = true")
	}

	var tmpl x509.Certificate
	nc.apply(&tmpl)
	if !tmpl.PermittedDNSDomainsCritical || len(tmpl.PermittedDNSDomains) != 2 || len(tmpl.ExcludedIPRanges) != 1 {
		t.Errorf("apply did not copy the constraints: %+v", tmpl)
	}
}

func TestParseNameConstraintsRejects(t *testing.T) {
	for _, in := range []string{
		"allowed;DNS:.klimax.internal",
		"permitted;.klimax.internal",
		"permitted;DNS:",
		"permitted;dirName:CN=x",
		"permitted;IP:10.0.0.0",
		"permitted;IP:10.0.0.0/33",
		"permitted;IP:10.0.0.0/ffff::",
		"permitted;IP:10.0.0.0/255.0.255.0",
	} {
		if _, err := ParseNameConstraints([]string{in}); err == nil {
			t.Errorf("ParseNameConstraints(%q): expected an error", in)
		}
	}
}

func TestPermittedDNSMismatch(t *testing.T) {
	cases := []struct {
		constraints []string
		name        string
		want        bool
	}{
		{nil, "a.klimax.internal", false},
		{[]string{"excluded;DNS:klimax.internal"}, "a.runlocal.dev", false},
		{[]string{"permitted;DNS:.klimax.internal"}, "a.bu1.klimax.internal", false},
		{[]string{"permitted;DNS:.klimax.internal"}, "klimax.internal", true},
		{[]string{"permitted;DNS:klimax.internal"}, "klimax.internal", false},
		{[]string{"permitted;DNS:klimax.internal"}, "notklimax.internal", true},
		{[]string{"permitted;DNS:.klimax.internal"}, "a.bu1.runlocal.dev", true},
		{[]string{"permitted;DNS:.other.internal", "DNS:.KLIMAX.internal"}, "a.klimax.internal", false},
	}
	for _, c := range cases {
		nc, err := ParseNameConstraints(c.constraints)
		if err != nil {
			t.Fatal(err)
		}
		if got := nc.PermittedDNSMismatch(c.name); got != c.want {
			t.Errorf("PermittedDNSMismatch(%q, %q) = %v, want %v", c.constraints, c.name, got, c.want)
		}
	}
}

func TestIsNameConstraintViolation(t *testing.T) {
	violation := x509.CertificateInvalidError{Reason: x509.CANotAuthorizedForThisName}
	if !IsNameConstraintViolation(fmt.Errorf("wrapped: %w", violation)) {
		t.Error("expected a wrapped CANotAuthorizedForThisName to be a violation")
	}
	if IsNameConstraintViolation(x509.CertificateInvalidError{Reason: x509.Expired}) {
		t.Error("an expired certificate is not a name constraint violation")
	}
	if IsNameConstraintViolation(nil) {
		t.Error("nil is not a violation")
	}
}
