package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// NameConstraints is the parsed form of the --name-constraint values given to a
// CA. Each name type holds its own permitted and excluded subtrees.
type NameConstraints struct {
	PermittedDNS, ExcludedDNS       []string
	PermittedIPs, ExcludedIPs       []*net.IPNet
	PermittedEmails, ExcludedEmails []string
	PermittedURIs, ExcludedURIs     []string
}

// ParseNameConstraints parses --name-constraint values written in openssl's
// syntax, `permitted;DNS:.example.internal` or `excluded;IP:10.0.0.0/8`. The
// `permitted;` prefix may be omitted. Types are DNS, IP, email and URI; IP
// ranges take CIDR notation or an address/netmask pair.
func ParseNameConstraints(values []string) (NameConstraints, error) {
	var nc NameConstraints
	for _, v := range values {
		if err := nc.add(v); err != nil {
			return NameConstraints{}, err
		}
	}
	return nc, nil
}

func (nc *NameConstraints) add(c string) error {
	raw := strings.TrimSpace(c)
	subtree := "permitted"
	if kind, rest, ok := strings.Cut(raw, ";"); ok {
		subtree = strings.ToLower(strings.TrimSpace(kind))
		raw = strings.TrimSpace(rest)
	}
	if subtree != "permitted" && subtree != "excluded" {
		return fmt.Errorf("name constraint %q: subtree must be permitted or excluded, got %q", c, subtree)
	}
	permitted := subtree == "permitted"

	typ, value, ok := strings.Cut(raw, ":")
	value = strings.TrimSpace(value)
	if !ok || value == "" {
		return fmt.Errorf("name constraint %q: expected [permitted|excluded;]TYPE:value, e.g. permitted;DNS:.example.internal", c)
	}

	pick := func(p, e *[]string) {
		if permitted {
			*p = append(*p, value)
		} else {
			*e = append(*e, value)
		}
	}
	switch strings.ToLower(typ) {
	case "dns":
		pick(&nc.PermittedDNS, &nc.ExcludedDNS)
	case "email":
		pick(&nc.PermittedEmails, &nc.ExcludedEmails)
	case "uri":
		pick(&nc.PermittedURIs, &nc.ExcludedURIs)
	case "ip":
		ipNet, err := parseIPConstraint(value)
		if err != nil {
			return fmt.Errorf("name constraint %q: %w", c, err)
		}
		if permitted {
			nc.PermittedIPs = append(nc.PermittedIPs, ipNet)
		} else {
			nc.ExcludedIPs = append(nc.ExcludedIPs, ipNet)
		}
	default:
		return fmt.Errorf("name constraint %q: type must be one of DNS, IP, email, URI, got %q", c, typ)
	}
	return nil
}

// parseIPConstraint accepts 10.0.0.0/8 or 10.0.0.0/255.0.0.0.
func parseIPConstraint(value string) (*net.IPNet, error) {
	addr, mask, ok := strings.Cut(value, "/")
	if !ok {
		return nil, fmt.Errorf("IP constraint needs a range, e.g. 10.0.0.0/8 or 10.0.0.0/255.0.0.0")
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address %q", addr)
	}
	bits := 8 * net.IPv6len
	if v4 := ip.To4(); v4 != nil {
		ip, bits = v4, 8*net.IPv4len
	}

	var ipMask net.IPMask
	if prefix, err := strconv.Atoi(mask); err == nil {
		if prefix < 0 || prefix > bits {
			return nil, fmt.Errorf("prefix length /%d out of range for %s", prefix, addr)
		}
		ipMask = net.CIDRMask(prefix, bits)
	} else {
		m := net.ParseIP(mask)
		if m == nil || (m.To4() != nil) != (bits == 8*net.IPv4len) {
			return nil, fmt.Errorf("invalid netmask %q for %s", mask, addr)
		}
		if v4 := m.To4(); v4 != nil {
			m = v4
		}
		ipMask = net.IPMask(m)
		if ones, size := ipMask.Size(); ones == 0 && size == 0 {
			return nil, fmt.Errorf("netmask %q is not contiguous", mask)
		}
	}
	return &net.IPNet{IP: ip.Mask(ipMask), Mask: ipMask}, nil
}

// ParseIPRange parses an IP range for a name constraint: CIDR (10.0.0.0/8) or
// an address/netmask pair (10.0.0.0/255.0.0.0). Host bits are cleared.
func ParseIPRange(s string) (*net.IPNet, error) {
	return parseIPConstraint(strings.TrimSpace(s))
}

// The Permit* and Exclude* methods build NameConstraints in code, without the
// openssl syntax. Each returns a copy with the subtrees appended, so they chain:
//
//	nc := pki.NameConstraints{}.PermitDNS(".klimax.internal").ExcludeIP(lan)
//
// DNS subtrees follow crypto/x509: ".example.internal" matches subdomains only,
// "example.internal" the domain and its subdomains.

// PermitDNS adds permitted DNS subtrees.
func (nc NameConstraints) PermitDNS(domains ...string) NameConstraints {
	nc.PermittedDNS = appendCopy(nc.PermittedDNS, domains)
	return nc
}

// ExcludeDNS adds excluded DNS subtrees.
func (nc NameConstraints) ExcludeDNS(domains ...string) NameConstraints {
	nc.ExcludedDNS = appendCopy(nc.ExcludedDNS, domains)
	return nc
}

// PermitIP adds permitted IP ranges; see ParseIPRange to build them from text.
func (nc NameConstraints) PermitIP(ranges ...*net.IPNet) NameConstraints {
	nc.PermittedIPs = appendCopy(nc.PermittedIPs, ranges)
	return nc
}

// ExcludeIP adds excluded IP ranges.
func (nc NameConstraints) ExcludeIP(ranges ...*net.IPNet) NameConstraints {
	nc.ExcludedIPs = appendCopy(nc.ExcludedIPs, ranges)
	return nc
}

// PermitEmail adds permitted email subtrees: a mailbox, a host, or a
// .domain for every host under it.
func (nc NameConstraints) PermitEmail(values ...string) NameConstraints {
	nc.PermittedEmails = appendCopy(nc.PermittedEmails, values)
	return nc
}

// ExcludeEmail adds excluded email subtrees.
func (nc NameConstraints) ExcludeEmail(values ...string) NameConstraints {
	nc.ExcludedEmails = appendCopy(nc.ExcludedEmails, values)
	return nc
}

// PermitURI adds permitted URI host subtrees.
func (nc NameConstraints) PermitURI(domains ...string) NameConstraints {
	nc.PermittedURIs = appendCopy(nc.PermittedURIs, domains)
	return nc
}

// ExcludeURI adds excluded URI host subtrees.
func (nc NameConstraints) ExcludeURI(domains ...string) NameConstraints {
	nc.ExcludedURIs = appendCopy(nc.ExcludedURIs, domains)
	return nc
}

// appendCopy appends to a fresh slice, so a NameConstraints value never
// shares a backing array with the one it was built from.
func appendCopy[T any](dst, src []T) []T {
	out := make([]T, 0, len(dst)+len(src))
	return append(append(out, dst...), src...)
}

// Empty reports whether no constraint was given.
func (nc NameConstraints) Empty() bool {
	return len(nc.PermittedDNS)+len(nc.ExcludedDNS)+len(nc.PermittedIPs)+len(nc.ExcludedIPs)+
		len(nc.PermittedEmails)+len(nc.ExcludedEmails)+len(nc.PermittedURIs)+len(nc.ExcludedURIs) == 0
}

// apply copies the constraints into a certificate template and marks the
// extension critical, as RFC 5280 requires.
func (nc NameConstraints) apply(tmpl *x509.Certificate) {
	if nc.Empty() {
		return
	}
	tmpl.PermittedDNSDomainsCritical = true
	tmpl.PermittedDNSDomains, tmpl.ExcludedDNSDomains = nc.PermittedDNS, nc.ExcludedDNS
	tmpl.PermittedIPRanges, tmpl.ExcludedIPRanges = nc.PermittedIPs, nc.ExcludedIPs
	tmpl.PermittedEmailAddresses, tmpl.ExcludedEmailAddresses = nc.PermittedEmails, nc.ExcludedEmails
	tmpl.PermittedURIDomains, tmpl.ExcludedURIDomains = nc.PermittedURIs, nc.ExcludedURIs
}

// PermittedDNSMismatch reports whether name falls outside every permitted DNS
// subtree. It returns false when there are no permitted DNS subtrees, since DNS
// names are then unconstrained. `.example.internal` matches subdomains only,
// `example.internal` matches the domain and its subdomains, as in crypto/x509.
func (nc NameConstraints) PermittedDNSMismatch(name string) bool {
	if len(nc.PermittedDNS) == 0 {
		return false
	}
	name = strings.ToLower(name)
	for _, p := range nc.PermittedDNS {
		p = strings.ToLower(p)
		if strings.HasPrefix(p, ".") {
			if strings.HasSuffix(name, p) {
				return false
			}
		} else if name == p || strings.HasSuffix(name, "."+p) {
			return false
		}
	}
	return true
}

// IsNameConstraintViolation reports whether a verification error comes from a
// CA in the chain not being allowed to issue for one of the leaf's names.
func IsNameConstraintViolation(err error) bool {
	var invalid x509.CertificateInvalidError
	return errors.As(err, &invalid) && invalid.Reason == x509.CANotAuthorizedForThisName
}
