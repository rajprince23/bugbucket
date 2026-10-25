<p align="center">
  <img src="https://img.shields.io/badge/version-2.1-0d1117?style=for-the-badge&labelColor=0d1117&color=58a6ff" />
  <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white" />
  <img src="https://img.shields.io/badge/Analysis-Local%20Rules-22c55e?style=for-the-badge" />
  <img src="https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-Linux-f97316?style=for-the-badge&logo=linux&logoColor=white" />
</p>

<p align="center">
  <b>Recon → Scan → Deterministic Rule Assessment → Report</b><br/>
  One command. Full attack surface. Zero noise.
</p>

---

## What is BugBasket?

BugBasket is a full-pipeline bug bounty automation CLI written in Go.  
It chains recon tools and vulnerability scanners into a single workflow, then applies deterministic local rules to findings. Reports retain scanner findings and clearly identify them as rule-assessed, not independently confirmed.

```
./bugbasket -d hackerone-target.com
```

That's it. BugBasket handles the rest.

---

## Modules

| Module | Engine | Finds |
|---|---|---|
| Subdomain Recon | subfinder · assetfinder · crt.sh · C99 | Subdomains |
| URL Discovery | waybackurls · katana | Endpoints, parameters, JS files |
| Live Detection | httpx | Live hosts, HTTP status, tech stack |
| Vulnerability Scan | nuclei (full templates) | CVEs, misconfigs, exposures, takeovers |
| CORS Testing | Built-in Go engine | Origin reflection, null origin, subdomain spoof, HTTP downgrade |
| Directory Fuzzing | ffuf | Hidden paths, admin panels, sensitive files |
| Vhost Discovery | ffuf (Host header) | Hidden virtual hosts |
| XSS | dalfox | Reflected & DOM XSS with PoC |
| SQLi | nuclei + param filter | SQL injection vectors |
| Hidden Params | arjun | Undocumented GET/POST parameters |
| Port Scan | nmap | Open ports |
| JS Analysis | Local regex rules | API keys, secrets, endpoints, buckets, tokens |
| Finding Analysis | Deterministic local rules | Severity adjustments, rule notes, remediation guidance |

---

## Kali Linux Setup

Use Go 1.24 or later and Git. The installer does not install Go. The CLI also requires `subfinder`, `httpx`, and `nuclei` on `PATH`, even if Nuclei is disabled in `config.yaml`.

```bash
git clone https://github.com/rajprince23/bugbucket.git
cd bugbucket
go version

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
export PATH="$(go env GOPATH)/bin:$PATH"

go build -o bugbasket ./cmd/main.go
```

Analysis runs locally and requires no provider credentials. `C99_API_KEY` is optional and only needed if you enable C99 passive reconnaissance.

Run from the project directory, replacing `example.com` with a domain you are authorized to test:

```bash
./bugbasket -d example.com --verbose
```

The current `config.yaml` enables recon and HTTP probing; other vulnerability scanners are disabled by default. Reports are written to `./reports`.

### Authorization and Target Scope

The domain supplied with `-d` or `-t` is the authorized scope. Active checks are limited to that exact domain and its subdomains; similarly named domains (for example, `example.com.attacker.test`) and unrelated hosts are rejected. Passive recon results may still include external URLs, but those URLs are not actively scanned. Active checks do not follow redirects to out-of-scope hosts. The `scanning.tools.httpx.follow_redirects` option cannot override this scope protection.

### CLI Options

- `-d`, `--domain` or `-t`, `--target`: target domain (required)
- `-c`, `--config`: config path (default `config.yaml`)
- `-o`, `--output`: report directory (default `./reports`)
- `-v`, `--verbose`: detailed progress
- `--skip-recon`, `--skip-scan`, `--js-only`: skip or limit phases
- `--nmap-xml <file>`: import open ports and service/version details from a local Nmap XML file; skips reconnaissance and all active scans. Supply `-d` with the authorized domain as usual. Only hosts whose XML hostname (or explicitly authorized IP address) is in scope are included.

---

## Output

Reports are saved to `./reports/` in Markdown:

```
reports/
└── bug_bounty_report_2026-04-04_16-41-25.md
```

### Report Structure

```
Executive Summary
  └── Risk score · Finding counts · Subdomains discovered

Critical Findings
  └── Title · URL · Evidence · Impact · Remediation · PoC (when enabled)

High / Medium / Low Findings
  └── Same structure

Subdomain List
  └── All discovered subdomains
```

Set `reporting.include_poc` in `config.yaml` to control whether proof-of-concept details appear in the report. Impact and remediation text is generated from deterministic local rules; it is guidance and does not establish exploitability.

Reports support `reporting.format: "markdown"` or `"json"` and `reporting.language: "en"` or `"ar"`. `reporting.severity_filter` accepts `critical`, `high`, `medium`, `low`, and `info`; when empty, reports include critical through low severity findings, matching the default report behavior.

Reports also include an OWASP Top 10:2021 coverage table based only on existing checks. Categories are marked `covered` when a mapped check completed, `not run` when mapped checks exist but none completed, or `not covered` when this project has no mapped check. This is an indicative mapping, not comprehensive OWASP coverage or a guarantee that a category is secure.

Offline Nmap XML imports produce informational open-port findings with any detected service, product, and version details. When `reporting.severity_filter` is empty, offline import mode includes informational findings in the generated report.

---

## CORS Severity Reference

BugBasket's built-in CORS engine tests multiple attack vectors and assigns severity  
based on actual exploitability — not just header presence:

| Pattern | Severity | Exploitable? |
|---|---|---|
| Origin reflected + `credentials: true` | **Critical** | Yes — any attacker site can steal authenticated data |
| Null origin + `credentials: true` | **High** | Yes — exploitable via sandboxed iframe |
| Subdomain spoof + `credentials: true` | **High** | Yes — attacker registers a matching domain |
| HTTP origin on HTTPS + `credentials: true` | **High** | Yes — requires network MITM position |
| Origin reflected, no credentials | **High** | Yes — public/unauthenticated data readable cross-origin |
| Subdomain spoof, no credentials | **Medium** | Partial — weak origin validation, no credentials |
| `*` + `credentials: true` | **Medium** | No — browsers reject this combination per CORS spec |

---

## Legal

> **BugBasket is for authorized security testing only.**  
> Only use this tool against systems you own or have **explicit written permission** to test.  
> Unauthorized scanning is illegal in most jurisdictions.  
> See [SECURITY.md](SECURITY.md) for the full responsible disclosure policy.

---

<p align="center">
  BugBasket &nbsp;·&nbsp; MIT License &nbsp;·&nbsp; v2.1
</p>
