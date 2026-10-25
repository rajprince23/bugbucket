package scope

import "testing"

func TestHostInScope(t *testing.T) {
	tests := []struct {
		host   string
		domain string
		want   bool
	}{
		{"example.com", "example.com", true},
		{"api.example.com", "example.com", true},
		{"API.EXAMPLE.COM.", "example.com", true},
		{"notexample.com", "example.com", false},
		{"example.com.attacker.test", "example.com", false},
		{"attacker.test", "example.com", false},
		{"192.0.2.1", "example.com", false},
		{"192.0.2.1", "192.0.2.1", true},
	}

	for _, test := range tests {
		if got := HostInScope(test.host, []string{test.domain}); got != test.want {
			t.Errorf("HostInScope(%q, %q) = %v, want %v", test.host, test.domain, got, test.want)
		}
	}
}

func TestURLInScope(t *testing.T) {
	tests := []struct {
		rawURL string
		want   bool
	}{
		{"https://example.com/path", true},
		{"http://api.example.com:8443/path", true},
		{"https://example.com.attacker.test/path", false},
		{"https://attacker.test/path", false},
		{"//example.com/path", false},
		{"file://example.com/path", false},
		{"https://user@example.com/path", false},
		{"not a URL", false},
	}

	for _, test := range tests {
		if got := URLInScope(test.rawURL, []string{"example.com"}); got != test.want {
			t.Errorf("URLInScope(%q) = %v, want %v", test.rawURL, got, test.want)
		}
	}
}
