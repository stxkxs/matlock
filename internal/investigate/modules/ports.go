package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/stxkxs/matlock/internal/investigate"
)

type portsResult struct {
	Open         []portEntry `json:"open"`
	Closed       []int       `json:"closed"`
	TotalScanned int         `json:"total_scanned"`
}

type portEntry struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	State   string `json:"state"`
}

// commonPorts maps port numbers to their well-known service names.
var commonPorts = map[int]string{
	21:    "ftp",
	22:    "ssh",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	143:   "imap",
	443:   "https",
	465:   "smtps",
	587:   "submission",
	993:   "imaps",
	995:   "pop3s",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	6379:  "redis",
	8080:  "http-alt",
	8443:  "https-alt",
	9200:  "elasticsearch",
	27017: "mongodb",
}

// portsModule performs TCP port scanning.
type portsModule struct {
	timeout     time.Duration
	concurrency int
}

// NewPortsModule creates a TCP port scanning module.
func NewPortsModule() investigate.Module {
	return &portsModule{
		timeout:     3 * time.Second,
		concurrency: 10,
	}
}

func (m *portsModule) Name() string        { return "ports" }
func (m *portsModule) Description() string  { return "TCP port scan of common service ports" }
func (m *portsModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{
		investigate.TargetDomain,
		investigate.TargetIPv4,
		investigate.TargetIPv6,
	}
}

func (m *portsModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	// Resolve domain to IP for consistent connection behavior
	addr, err := m.resolveTarget(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("ports: resolve target: %w", err)
	}

	ports := sortedPorts()

	var mu sync.Mutex
	var openPorts []portEntry
	var closedPorts []int

	sem := make(chan struct{}, m.concurrency)
	var wg sync.WaitGroup

	for _, port := range ports {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("ports: context cancelled: %w", err)
		}

		port := port
		wg.Add(1)
		sem <- struct{}{}

		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()

			if ctx.Err() != nil {
				return
			}

			open := m.scanPort(ctx, addr, port)

			mu.Lock()
			defer mu.Unlock()
			if open {
				openPorts = append(openPorts, portEntry{
					Port:    port,
					Service: commonPorts[port],
					State:   "open",
				})
			} else {
				closedPorts = append(closedPorts, port)
			}
		}()
	}

	wg.Wait()

	// Sort results for deterministic output
	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})
	sort.Ints(closedPorts)

	result := portsResult{
		Open:         openPorts,
		Closed:       closedPorts,
		TotalScanned: len(ports),
	}
	if result.Open == nil {
		result.Open = make([]portEntry, 0)
	}
	if result.Closed == nil {
		result.Closed = make([]int, 0)
	}

	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("ports: marshal result: %w", err)
	}

	return data, nil
}

// scanPort attempts a TCP connection to the given address and port.
func (m *portsModule) scanPort(ctx context.Context, addr string, port int) bool {
	target := fmt.Sprintf("%s:%d", addr, port)

	dialer := &net.Dialer{
		Timeout: m.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// resolveTarget resolves a domain to an IP address, or returns the IP directly.
func (m *portsModule) resolveTarget(ctx context.Context, target string) (string, error) {
	// If it's already an IP, use it directly
	if ip := net.ParseIP(target); ip != nil {
		// Wrap IPv6 in brackets for net.Dial compatibility
		if ip.To4() == nil {
			return "[" + ip.String() + "]", nil
		}
		return ip.String(), nil
	}

	// Resolve domain to IP
	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, target)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", target, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("resolve %s: no addresses found", target)
	}

	// Prefer IPv4 if available
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			return a, nil
		}
	}

	// Fall back to first address (IPv6)
	ip := net.ParseIP(addrs[0])
	if ip != nil && ip.To4() == nil {
		return "[" + addrs[0] + "]", nil
	}
	return addrs[0], nil
}

// sortedPorts returns the common ports in sorted order.
func sortedPorts() []int {
	ports := make([]int, 0, len(commonPorts))
	for p := range commonPorts {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}
