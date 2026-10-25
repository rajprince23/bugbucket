package scope

import (
	"net"
	"net/url"
	"strings"
)

func HostInScope(host string, authorizedDomains []string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}

	for _, domain := range authorizedDomains {
		domain = normalizeHost(domain)
		if domain == "" {
			continue
		}
		if host == domain {
			return true
		}
		if net.ParseIP(host) == nil && net.ParseIP(domain) == nil && strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func URLInScope(rawURL string, authorizedDomains []string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.User != nil || parsed.Hostname() == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return false
	}
	return HostInScope(parsed.Hostname(), authorizedDomains)
}

func HostFromTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}

	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err != nil || parsed.User != nil {
			return ""
		}
		return normalizeHost(parsed.Hostname())
	}

	parsed, err := url.Parse("//" + target)
	if err != nil || parsed.User != nil {
		return ""
	}
	return normalizeHost(parsed.Hostname())
}

func normalizeHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return host
}
