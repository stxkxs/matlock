package investigate

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// NormalizeTarget strips protocols, ports, paths, and lowercases the input.
func NormalizeTarget(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.ToLower(s)

	// Strip protocol
	for _, prefix := range []string{"https://", "http://", "ftp://", "ftps://"} {
		s = strings.TrimPrefix(s, prefix)
	}

	// Strip path
	if i := strings.Index(s, "/"); i != -1 {
		s = s[:i]
	}

	// Strip port
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}

	// Strip trailing dot (FQDN notation)
	s = strings.TrimSuffix(s, ".")

	return s
}

// DetectTargetType classifies the normalized target.
func DetectTargetType(target string) (TargetType, error) {
	if target == "" {
		return "", fmt.Errorf("empty target")
	}

	// Check IPv4
	if ip := net.ParseIP(target); ip != nil {
		if ip.To4() != nil {
			return TargetIPv4, nil
		}
		return TargetIPv6, nil
	}

	// Check bracketed IPv6 (e.g. [::1])
	if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		inner := target[1 : len(target)-1]
		if ip := net.ParseIP(inner); ip != nil {
			return TargetIPv6, nil
		}
	}

	// Check domain
	if domainRegex.MatchString(target) {
		return TargetDomain, nil
	}

	return "", fmt.Errorf("invalid target %q: not a valid domain, IPv4, or IPv6 address", target)
}

// ValidateTarget normalizes and validates the input, returning the cleaned target and its type.
func ValidateTarget(raw string) (string, TargetType, error) {
	target := NormalizeTarget(raw)
	tt, err := DetectTargetType(target)
	if err != nil {
		return "", "", err
	}
	return target, tt, nil
}

// IsPrivateIP returns true if the IP falls in RFC 1918 / link-local / loopback ranges.
func IsPrivateIP(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// GetApexDomain extracts the registrable domain, handling multi-part TLDs.
func GetApexDomain(domain string) string {
	multiPartTLDs := []string{
		".co.uk", ".co.jp", ".co.kr", ".co.nz", ".co.za", ".co.in",
		".com.au", ".com.br", ".com.cn", ".com.mx", ".com.tw",
		".org.uk", ".net.au", ".ac.uk", ".gov.uk",
	}
	lower := strings.ToLower(domain)
	for _, tld := range multiPartTLDs {
		if strings.HasSuffix(lower, tld) {
			prefix := strings.TrimSuffix(lower, tld)
			parts := strings.Split(prefix, ".")
			return parts[len(parts)-1] + tld
		}
	}
	parts := strings.Split(lower, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return lower
}
