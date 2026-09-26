package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// nameConstraintTypes maps the accepted name types (case-insensitive) to
// openssl's spelling.
var nameConstraintTypes = map[string]string{
	"dns":     "DNS",
	"ip":      "IP",
	"email":   "email",
	"uri":     "URI",
	"dirname": "dirName",
}

// NameConstraintsExt turns --name-constraint values into the value of an
// openssl `nameConstraints` extension line, marked critical. Each value uses
// openssl's syntax, `permitted;DNS:.example.internal` or
// `excluded;IP:10.0.0.0/255.0.0.0`; the `permitted;` prefix may be omitted.
// IP ranges also accept CIDR notation (10.0.0.0/8), which is converted to the
// address/netmask form openssl requires. Returns "" when there is nothing to add.
func NameConstraintsExt(constraints []string) (string, error) {
	if len(constraints) == 0 {
		return "", nil
	}
	parts := []string{"critical"}
	for _, c := range constraints {
		norm, err := normalizeNameConstraint(c)
		if err != nil {
			return "", err
		}
		parts = append(parts, norm)
	}
	return strings.Join(parts, ","), nil
}

func normalizeNameConstraint(c string) (string, error) {
	raw := strings.TrimSpace(c)
	subtree := "permitted"
	if kind, rest, ok := strings.Cut(raw, ";"); ok {
		subtree = strings.ToLower(strings.TrimSpace(kind))
		raw = strings.TrimSpace(rest)
	}
	if subtree != "permitted" && subtree != "excluded" {
		return "", fmt.Errorf("name constraint %q: subtree must be permitted or excluded, got %q", c, subtree)
	}

	typ, value, ok := strings.Cut(raw, ":")
	if !ok || value == "" {
		return "", fmt.Errorf("name constraint %q: expected [permitted|excluded;]TYPE:value, e.g. permitted;DNS:.example.internal", c)
	}
	name, known := nameConstraintTypes[strings.ToLower(typ)]
	if !known {
		return "", fmt.Errorf("name constraint %q: type must be one of DNS, IP, email, URI, dirName, got %q", c, typ)
	}
	if name == "IP" {
		ipRange, err := ipConstraintRange(value)
		if err != nil {
			return "", fmt.Errorf("name constraint %q: %w", c, err)
		}
		value = ipRange
	}
	if strings.Contains(value, ",") {
		return "", fmt.Errorf("name constraint %q: value must not contain a comma", c)
	}
	return fmt.Sprintf("%s;%s:%s", subtree, name, value), nil
}

// ipConstraintRange validates an IP name constraint and returns it in openssl's
// address/netmask form. Both 10.0.0.0/8 and 10.0.0.0/255.0.0.0 are accepted.
func ipConstraintRange(value string) (string, error) {
	addr, mask, ok := strings.Cut(value, "/")
	if !ok {
		return "", fmt.Errorf("IP constraint needs a range, e.g. 10.0.0.0/8 or 10.0.0.0/255.0.0.0")
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address %q", addr)
	}
	bits := 8 * net.IPv6len
	if ip.To4() != nil {
		bits = 8 * net.IPv4len
	}
	if prefix, err := strconv.Atoi(mask); err == nil {
		if prefix < 0 || prefix > bits {
			return "", fmt.Errorf("prefix length /%d out of range for %s", prefix, addr)
		}
		return fmt.Sprintf("%s/%s", addr, net.IP(net.CIDRMask(prefix, bits))), nil
	}
	m := net.ParseIP(mask)
	if m == nil || (m.To4() != nil) != (ip.To4() != nil) {
		return "", fmt.Errorf("invalid netmask %q for %s", mask, addr)
	}
	return value, nil
}

// PermittedDNSMismatch reports whether name falls outside every permitted DNS
// subtree in constraints. It returns false when there are no permitted DNS
// subtrees, since DNS names are then unconstrained. Matching follows openssl
// and Go: `.example.internal` matches subdomains only, `example.internal`
// matches the domain and its subdomains.
func PermittedDNSMismatch(constraints []string, name string) bool {
	name = strings.ToLower(name)
	var permitted []string
	for _, c := range constraints {
		norm, err := normalizeNameConstraint(c)
		if err != nil {
			continue
		}
		if dns, ok := strings.CutPrefix(norm, "permitted;DNS:"); ok {
			permitted = append(permitted, strings.ToLower(dns))
		}
	}
	if len(permitted) == 0 {
		return false
	}
	for _, p := range permitted {
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
