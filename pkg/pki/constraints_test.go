package pki

import (
	"crypto/x509"
	"fmt"
	"testing"
)

func TestNameConstraintsExt(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"permitted;DNS:.klimax.internal"}, "critical,permitted;DNS:.klimax.internal"},
		{[]string{"DNS:klimax.internal"}, "critical,permitted;DNS:klimax.internal"},
		{[]string{"Excluded;dns:bad.klimax.internal"}, "critical,excluded;DNS:bad.klimax.internal"},
		{[]string{"permitted;IP:10.0.0.0/8"}, "critical,permitted;IP:10.0.0.0/255.0.0.0"},
		{[]string{"permitted;IP:192.168.0.0/255.255.0.0"}, "critical,permitted;IP:192.168.0.0/255.255.0.0"},
		{[]string{"permitted;IP:fd00::/8"}, "critical,permitted;IP:fd00::/ff00::"},
		{
			[]string{"permitted;DNS:.klimax.internal", "permitted;email:.klimax.internal"},
			"critical,permitted;DNS:.klimax.internal,permitted;email:.klimax.internal",
		},
	}
	for _, c := range cases {
		got, err := NameConstraintsExt(c.in)
		if err != nil {
			t.Errorf("NameConstraintsExt(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NameConstraintsExt(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNameConstraintsExtRejects(t *testing.T) {
	for _, in := range []string{
		"allowed;DNS:.klimax.internal",
		"permitted;.klimax.internal",
		"permitted;DNS:",
		"permitted;RID:1.2.3",
		"permitted;IP:10.0.0.0",
		"permitted;IP:10.0.0.0/33",
		"permitted;IP:10.0.0.0/ffff::",
		"permitted;DNS:a.internal,b.internal",
	} {
		if _, err := NameConstraintsExt([]string{in}); err == nil {
			t.Errorf("NameConstraintsExt(%q): expected an error", in)
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
		if got := PermittedDNSMismatch(c.constraints, c.name); got != c.want {
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
