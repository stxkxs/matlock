package investigate

import "testing"

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"https://example.com", "example.com"},
		{"http://example.com/path/to/page", "example.com"},
		{"https://example.com:8443/api", "example.com"},
		{"  example.com  ", "example.com"},
		{"example.com.", "example.com"},
		{"ftp://files.example.com", "files.example.com"},
		{"192.168.1.1", "192.168.1.1"},
		{"https://192.168.1.1:443", "192.168.1.1"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeTarget(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeTarget(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDetectTargetType(t *testing.T) {
	tests := []struct {
		input   string
		want    TargetType
		wantErr bool
	}{
		{"example.com", TargetDomain, false},
		{"sub.example.com", TargetDomain, false},
		{"a.b.c.example.co.uk", TargetDomain, false},
		{"192.168.1.1", TargetIPv4, false},
		{"8.8.8.8", TargetIPv4, false},
		{"::1", TargetIPv6, false},
		{"2001:db8::1", TargetIPv6, false},
		{"", "", true},
		{"not valid!", "", true},
		{"-invalid.com", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := DetectTargetType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DetectTargetType(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DetectTargetType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateTarget(t *testing.T) {
	target, tt, err := ValidateTarget("https://Example.COM/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target != "example.com" {
		t.Errorf("got target %q, want %q", target, "example.com")
	}
	if tt != TargetDomain {
		t.Errorf("got type %q, want %q", tt, TargetDomain)
	}

	target, tt, err = ValidateTarget("8.8.8.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target != "8.8.8.8" {
		t.Errorf("got target %q, want %q", target, "8.8.8.8")
	}
	if tt != TargetIPv4 {
		t.Errorf("got type %q, want %q", tt, TargetIPv4)
	}

	_, _, err = ValidateTarget("not valid!")
	if err == nil {
		t.Error("expected error for invalid target")
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"not-an-ip", false},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := IsPrivateIP(tt.ip); got != tt.want {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestGetApexDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"www.example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"example.com", "example.com"},
		{"www.example.co.uk", "example.co.uk"},
		{"sub.domain.example.co.uk", "example.co.uk"},
		{"www.example.com.au", "example.com.au"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := GetApexDomain(tt.input); got != tt.want {
				t.Errorf("GetApexDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
