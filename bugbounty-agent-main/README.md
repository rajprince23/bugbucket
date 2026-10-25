<p align="center">
  <img src="logo.png" alt="HawkEye" width="720" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.1-0d1117?style=for-the-badge&labelColor=0d1117&color=58a6ff" />
  <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white" />
  <img src="https://img.shields.io/badge/AI-DeepSeek%20%7C%20Claude%20%7C%20GPT--4-a855f7?style=for-the-badge" />
  <img src="https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-Linux-f97316?style=for-the-badge&logo=linux&logoColor=white" />
</p>

<p align="center">
  <b>Recon → Scan → AI Validation → Report</b><br/>
  One command. Full attack surface. Zero noise.
</p>

---

## What is HawkEye?

HawkEye is a full-pipeline bug bounty automation agent written in Go.  
It chains recon tools, vulnerability scanners, and an AI validator into a single workflow —  
producing a clean, analyst-grade report with confirmed findings only.

```
./hawkeye -d hackerone-target.com
```

That's it. HawkEye handles the rest.

---

## Pipeline

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                         TARGET DOMAIN                            │
  └─────────────────────────────┬────────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  PHASE 1 — RECON                                                │
  │                                                                 │
  │  subfinder · assetfinder · crt.sh · C99.nl · waybackurls       │
  │  katana                                                         │
  │                                                                 │
  │  → subdomains · live URLs · JS files · parameters              │
  └─────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  PHASE 2 — SCANNING (parallel)                                  │
  │                                                                 │
  │  httpx         → live host detection + status codes            │
  │  nuclei        → CVEs · misconfigs · exposures · takeovers     │
  │  CORS engine   → origin reflection · null · subdomain spoof    │
  │  ffuf          → hidden paths · admin panels · vhost fuzzing   │
  │  dalfox        → reflected & DOM XSS with PoC                  │
  │  arjun         → undocumented GET/POST parameters              │
  │  nmap          → open ports                                     │
  │  SQLi scanner  → injection via parameter analysis              │
  └─────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  PHASE 2.5 — JS ANALYSIS                                        │
  │                                                                 │
  │  Regex engine  → API keys · secrets · endpoints · S3 buckets   │
  │  AI (LLM)      → deep analysis of app bundles (12KB/file)      │
  │                                                                 │
  │  Detects: AWS/GitHub/Stripe/Firebase keys · JWT tokens         │
  │           hardcoded passwords · internal API routes            │
  │           DOM XSS sinks · postMessage issues                   │
  └─────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  PHASE 3 — AI VALIDATION                                        │
  │                                                                 │
  │  Every finding is reviewed by the AI:                          │
  │  · Confirms real vs false positive                             │
  │  · Assigns CVSS-informed severity                              │
  │  · Generates PoC for each confirmed finding                    │
  │  · Writes impact assessment + remediation                      │
  └─────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  PHASE 4 — REPORT                                               │
  │                                                                 │
  │  Markdown report with:                                         │
  │  · Executive summary · Risk score · Severity breakdown         │
  │  · Confirmed findings only · Evidence + PoC per finding        │
  └─────────────────────────────────────────────────────────────────┘
```

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
| JS Analysis | Regex + LLM | API keys, secrets, endpoints, S3 buckets, tokens |
| AI Validation | DeepSeek / Claude / GPT-4 | False positive filtering + PoC generation |

---

## Kali Linux Setup

Use Go 1.24 or later and Git. The installer does not install Go. The CLI also requires `subfinder`, `httpx`, and `nuclei` on `PATH`, even if Nuclei is disabled in `config.yaml`.

```bash
git clone https://github.com/Btr4k/bugbounty-agent.git
cd bugbounty-agent
go version

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
export PATH="$(go env GOPATH)/bin:$PATH"

go build -o hawkeye ./cmd/main.go
cp .env.example .env
nano .env
```

In `.env`, set a valid key for exactly one supported provider: `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, `OPENAI_API_KEY`, or `OPENROUTER_API_KEY`. The provider is auto-detected. Keep the key private; do not commit `.env`.

Run from the project directory, replacing `example.com` with a domain you are authorized to test:

```bash
./hawkeye -d example.com --verbose
```

The current `config.yaml` enables recon and HTTP probing; other vulnerability scanners are disabled by default. Reports are written to `./reports`.

### CLI Options

- `-d`, `--domain` or `-t`, `--target`: target domain (required)
- `-c`, `--config`: config path (default `config.yaml`)
- `-o`, `--output`: report directory (default `./reports`)
- `-v`, `--verbose`: detailed progress
- `--skip-recon`, `--skip-scan`, `--js-only`: skip or limit phases
- `--ai-provider`, `--ai-model`: override the configured provider or model

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
  └── Title · URL · Evidence · AI Analysis · PoC

High / Medium / Low Findings
  └── Same structure

Subdomain List
  └── All discovered subdomains
```

---

## CORS Severity Reference

HawkEye's built-in CORS engine tests multiple attack vectors and assigns severity  
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

> **HawkEye is for authorized security testing only.**  
> Only use this tool against systems you own or have **explicit written permission** to test.  
> Unauthorized scanning is illegal in most jurisdictions.  
> See [SECURITY.md](SECURITY.md) for the full responsible disclosure policy.

---

<p align="center">
  Built by <a href="https://x.com/A_cyb3r">@A_cyb3r</a> &nbsp;·&nbsp; MIT License &nbsp;·&nbsp; v2.1
</p>
