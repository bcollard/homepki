package pki

import "testing"

func TestBuildSANSection(t *testing.T) {
	got, err := BuildSANSection("alt", []string{
		"gw.bu1.test.local",
		"kong.local",
		"192.168.1.10",
		"IP:::1",
		"DNS:*.kong.local",
		"email:admin@kong.local",
		"URI:https://kong.local/",
		"dns:lowercase.example",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "[ alt ]\nDNS.1 = gw.bu1.test.local\nDNS.2 = kong.local\nIP.1 = 192.168.1.10\nIP.2 = ::1\nDNS.3 = *.kong.local\nemail.1 = admin@kong.local\nURI.1 = https://kong.local/\nDNS.4 = lowercase.example\n"
	if got != want {
		t.Fatalf("mismatch:\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestBuildSANSectionErrors(t *testing.T) {
	cases := []string{"", "   ", "IP:not-an-ip", "DNS:"}
	for _, c := range cases {
		if _, err := BuildSANSection("alt", []string{c}); err == nil {
			t.Errorf("expected error for input %q, got nil", c)
		}
	}
}
