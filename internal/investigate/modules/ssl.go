package modules

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/stxkxs/matlock/internal/investigate"
)

type sslResult struct {
	Valid        bool      `json:"valid"`
	Certificates []sslCert `json:"certificates"`
}

type sslCert struct {
	Host       string   `json:"host"`
	Connected  bool     `json:"connected"`
	Subject    string   `json:"subject"`
	Issuer     string   `json:"issuer"`
	SANs       []string `json:"sans"`
	NotBefore  string   `json:"not_before"`
	NotAfter   string   `json:"not_after"`
	DaysLeft   int      `json:"days_left"`
	Expired    bool     `json:"expired"`
	Serial     string   `json:"serial"`
	SigAlg     string   `json:"sig_alg"`
	TLSVersion string   `json:"tls_version"`
	Error      string   `json:"error,omitempty"`
}

// sslModule performs TLS certificate analysis.
type sslModule struct {
	timeout time.Duration
}

// NewSSLModule creates a TLS certificate analysis module.
func NewSSLModule() investigate.Module {
	return &sslModule{
		timeout: 5 * time.Second,
	}
}

func (m *sslModule) Name() string        { return "ssl" }
func (m *sslModule) Description() string  { return "TLS certificate chain analysis and expiration check" }
func (m *sslModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

func (m *sslModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	hosts := []string{target, "www." + target, "app." + target, "api." + target}

	result := sslResult{
		Valid:        true,
		Certificates: make([]sslCert, 0, len(hosts)),
	}

	var errs []string

	for _, host := range hosts {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("ssl: context cancelled: %w", err)
		}

		cert := m.checkHost(host)
		result.Certificates = append(result.Certificates, cert)

		if host == target && (cert.Expired || !cert.Connected) {
			result.Valid = false
		}
	}

	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("ssl: marshal result: %w", err)
	}

	if len(errs) > 0 {
		return data, fmt.Errorf("ssl: partial errors: %s", strings.Join(errs, "; "))
	}

	return data, nil
}

func (m *sslModule) checkHost(host string) sslCert {
	entry := sslCert{
		Host: host,
		SANs: make([]string, 0),
	}

	dialer := &net.Dialer{
		Timeout: m.timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
	})
	if err != nil {
		// Retry with InsecureSkipVerify to still get cert info
		conn, err = tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})
		if err != nil {
			entry.Connected = false
			entry.Error = fmt.Sprintf("connect: %v", err)
			return entry
		}
	}
	defer conn.Close()

	entry.Connected = true

	state := conn.ConnectionState()
	entry.TLSVersion = tlsVersionString(state.Version)

	certs := state.PeerCertificates
	if len(certs) == 0 {
		entry.Error = "no peer certificates"
		return entry
	}

	leaf := certs[0]
	now := time.Now()

	entry.Subject = leaf.Subject.CommonName
	entry.Issuer = leaf.Issuer.CommonName
	entry.SANs = leaf.DNSNames
	if entry.SANs == nil {
		entry.SANs = make([]string, 0)
	}
	entry.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	entry.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	entry.Expired = now.After(leaf.NotAfter)
	entry.DaysLeft = int(time.Until(leaf.NotAfter).Hours() / 24)
	entry.Serial = formatSerial(leaf.SerialNumber)
	entry.SigAlg = leaf.SignatureAlgorithm.String()

	return entry
}

// tlsVersionString returns a human-readable TLS version string.
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}

// formatSerial formats a certificate serial number as a colon-separated hex string.
func formatSerial(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	hex := fmt.Sprintf("%X", serial.Bytes())
	if len(hex)%2 != 0 {
		hex = "0" + hex
	}
	var parts []string
	for i := 0; i < len(hex); i += 2 {
		parts = append(parts, hex[i:i+2])
	}
	return strings.Join(parts, ":")
}
