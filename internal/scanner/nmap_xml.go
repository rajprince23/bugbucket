package scanner

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Btr4k/bugbounty-agent/internal/scope"
)

const maxNmapXMLSize = 32 << 20

type nmapXMLDocument struct {
	XMLName xml.Name      `xml:"nmaprun"`
	Hosts   []nmapXMLHost `xml:"host"`
}

type nmapXMLHost struct {
	Addresses []struct {
		Address string `xml:"addr,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports []nmapXMLPort `xml:"ports>port"`
}

type nmapXMLPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   string `xml:"portid,attr"`
	State    struct {
		Name string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name     string `xml:"name,attr"`
		Product  string `xml:"product,attr"`
		Version  string `xml:"version,attr"`
		Extra    string `xml:"extrainfo,attr"`
		Tunnel   string `xml:"tunnel,attr"`
		Method   string `xml:"method,attr"`
		Accuracy string `xml:"conf,attr"`
	} `xml:"service"`
}

// ImportNmapXML parses local Nmap XML output and returns findings for hosts in
// the explicitly authorized scope. It performs no network activity.
func ImportNmapXML(path string, authorizedDomains []string) ([]Finding, error) {
	if len(authorizedDomains) == 0 {
		return nil, fmt.Errorf("Nmap XML import requires an explicitly authorized target")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open XML file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxNmapXMLSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read XML file: %w", err)
	}
	if len(data) > maxNmapXMLSize {
		return nil, fmt.Errorf("Nmap XML file exceeds the %d MiB size limit", maxNmapXMLSize>>20)
	}

	var document nmapXMLDocument
	if err := xml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("invalid Nmap XML: %w", err)
	}
	if document.XMLName.Local != "nmaprun" {
		return nil, fmt.Errorf("invalid Nmap XML: expected <nmaprun> root element")
	}

	findings := make([]Finding, 0)
	timestamp := time.Now().Format(time.RFC3339)
	for _, host := range document.Hosts {
		target := scopedNmapHost(host, authorizedDomains)
		if target == "" {
			continue
		}

		for _, port := range host.Ports {
			if !strings.EqualFold(port.State.Name, "open") {
				continue
			}
			portNumber, err := strconv.ParseUint(port.PortID, 10, 16)
			if err != nil || portNumber == 0 {
				return nil, fmt.Errorf("invalid open-port number %q in Nmap XML", port.PortID)
			}
			protocol := strings.ToLower(strings.TrimSpace(port.Protocol))
			if protocol == "" {
				return nil, fmt.Errorf("open port %s has no protocol in Nmap XML", port.PortID)
			}

			serviceParts := make([]string, 0, 3)
			if port.Service.Name != "" {
				serviceParts = append(serviceParts, port.Service.Name)
			}
			productVersion := strings.TrimSpace(strings.Join([]string{
				port.Service.Product,
				port.Service.Version,
			}, " "))
			if productVersion != "" {
				serviceParts = append(serviceParts, productVersion)
			}
			if port.Service.Extra != "" {
				serviceParts = append(serviceParts, port.Service.Extra)
			}

			title := fmt.Sprintf("Open %s port %d on %s", strings.ToUpper(protocol), portNumber, target)
			if len(serviceParts) > 0 {
				title += " (" + strings.Join(serviceParts, ", ") + ")"
			}

			metadata := map[string]string{
				"protocol": protocol,
				"port":     strconv.FormatUint(portNumber, 10),
				"state":    "open",
			}
			addNmapMetadata(metadata, "service", port.Service.Name)
			addNmapMetadata(metadata, "product", port.Service.Product)
			addNmapMetadata(metadata, "version", port.Service.Version)
			addNmapMetadata(metadata, "extrainfo", port.Service.Extra)
			addNmapMetadata(metadata, "tunnel", port.Service.Tunnel)
			addNmapMetadata(metadata, "method", port.Service.Method)
			addNmapMetadata(metadata, "service_confidence", port.Service.Accuracy)

			evidence := fmt.Sprintf("Protocol: %s; Port: %d; State: open", protocol, portNumber)
			if len(serviceParts) > 0 {
				evidence += "; Service: " + strings.Join(serviceParts, ", ")
			}
			findings = append(findings, Finding{
				ID:          "nmap-import-open-port",
				Title:       title,
				Description: "Open-port and service information imported from a local Nmap XML file; no scan was run.",
				Severity:    "info",
				Type:        "port-scan",
				Target:      target,
				Evidence:    evidence,
				Metadata:    metadata,
				Timestamp:   timestamp,
			})
		}
	}

	return findings, nil
}

func scopedNmapHost(host nmapXMLHost, authorizedDomains []string) string {
	for _, hostname := range host.Hostnames {
		if scope.HostInScope(hostname.Name, authorizedDomains) {
			return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname.Name)), ".")
		}
	}
	for _, address := range host.Addresses {
		if scope.HostInScope(address.Address, authorizedDomains) {
			return address.Address
		}
	}
	return ""
}

func addNmapMetadata(metadata map[string]string, key, value string) {
	if value = strings.TrimSpace(value); value != "" {
		metadata[key] = value
	}
}
