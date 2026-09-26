package pki

import (
	"net"
	"reflect"
	"testing"
)

func TestParseSANs(t *testing.T) {
	got, err := ParseSANs([]string{
		"gw.bu1.test.local",
		"kong.local",
		"192.168.1.10",
		"IP:::1",
		"DNS:*.kong.local",
		"email:admin@kong.local",
		"URI:spiffe://kong.local/gw",
		"dns:lowercase.example",
		"kong.local",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []string{"gw.bu1.test.local", "kong.local", "*.kong.local", "lowercase.example"}; !reflect.DeepEqual(got.DNS, want) {
		t.Errorf("DNS = %q, want %q", got.DNS, want)
	}
	if len(got.IPs) != 2 || !got.IPs[0].Equal(net.ParseIP("192.168.1.10")) || !got.IPs[1].Equal(net.IPv6loopback) {
		t.Errorf("IPs = %v", got.IPs)
	}
	if !reflect.DeepEqual(got.Emails, []string{"admin@kong.local"}) {
		t.Errorf("Emails = %q", got.Emails)
	}
	if len(got.URIs) != 1 || got.URIs[0].String() != "spiffe://kong.local/gw" {
		t.Errorf("URIs = %v", got.URIs)
	}
	if got.Count() != 8 {
		t.Errorf("Count() = %d, want 8", got.Count())
	}
}

func TestParseSANsErrors(t *testing.T) {
	cases := []string{"", "   ", "IP:not-an-ip", "DNS:", "URI:no-scheme"}
	for _, c := range cases {
		if _, err := ParseSANs([]string{c}); err == nil {
			t.Errorf("expected error for input %q, got nil", c)
		}
	}
}
