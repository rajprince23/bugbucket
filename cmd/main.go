package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Btr4k/bugbounty-agent/internal/analyzer"
	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
	"github.com/Btr4k/bugbounty-agent/internal/recon"
	"github.com/Btr4k/bugbounty-agent/internal/reporter"
	"github.com/Btr4k/bugbounty-agent/internal/scanner"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	cfgFile      string
	targetDomain string
	outputDir    string
	verbose      bool
	skipRecon    bool
	skipScan     bool
	jsOnly       bool
	nmapXMLFile  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "bugbasket",
		Short: "BugBasket - Rule-Based Bug Bounty Hunting Tool",
		Long:  banner(),
		RunE:  runAgent,
	}

	rootCmd.Flags().StringVarP(&cfgFile, "config", "c", "config.yaml", "Config file")
	rootCmd.Flags().StringVarP(&targetDomain, "target", "t", "", "Target domain")
	rootCmd.Flags().StringVarP(&targetDomain, "domain", "d", "", "Target domain (alias for -t/--target)")
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().BoolVar(&skipRecon, "skip-recon", false, "Skip the reconnaissance phase")
	rootCmd.Flags().BoolVar(&skipScan, "skip-scan", false, "Skip the vulnerability scanning phase")
	rootCmd.Flags().BoolVar(&jsOnly, "js-only", false, "Run JS file analysis only (skips vulnerability scanning)")
	rootCmd.Flags().StringVar(&nmapXMLFile, "nmap-xml", "", "Import an Nmap XML file offline (skips recon and all active scans)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runAgent(cmd *cobra.Command, args []string) error {
	printBanner()

	// Validate that at least -t/--target or -d/--domain was provided
	if targetDomain == "" {
		return fmt.Errorf("target domain is required: use -t <domain> or -d <domain>")
	}

	// Initialize logger
	log := logger.New(verbose)
	defer log.Close()

	// Load config
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Validate target domain (prevent command injection)
	if err := validateDomain(targetDomain); err != nil {
		return fmt.Errorf("invalid target domain: %w", err)
	}

	offlineImport := nmapXMLFile != ""
	runRecon := cfg.Recon.Enabled && !skipRecon && !offlineImport
	runScan := cfg.Scanning.Enabled && !skipScan && !jsOnly && !offlineImport
	if runRecon || runScan {
		// Validate required tools are installed before wasting time
		checkTools(log, cfg, runRecon, runScan)
	}

	// Add target domain to config
	cfg.Target.Domains = []string{targetDomain}
	if cmd.Flags().Changed("output") {
		cfg.Reporting.OutputDir = outputDir
	} else if cfg.Reporting.OutputDir == "" {
		cfg.Reporting.OutputDir = "./reports"
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Warn("Received interrupt signal, shutting down...")
		cancel()
	}()

	startTime := time.Now()

	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	white := color.New(color.FgWhite, color.Bold)
	dim := color.New(color.FgHiBlack)

	// Target info
	fmt.Println()
	white.Printf("  🎯 Target: ")
	cyan.Printf("%s\n", targetDomain)
	dim.Printf("  ⏰ Started: %s\n", startTime.Format("2006-01-02 15:04:05"))
	fmt.Println()

	white.Printf("  🧭 Analysis:    ")
	cyan.Println("Deterministic local rules")
	fmt.Println()

	// ═══════════════════════════════════════
	// Phase 1: Reconnaissance
	// ═══════════════════════════════════════
	var reconResults *recon.Results
	phaseStart := time.Now()

	if skipRecon || offlineImport || !cfg.Recon.Enabled {
		if offlineImport {
			dim.Println("  ⏭️  Skipping reconnaissance phase (--nmap-xml: offline import mode)")
		} else if !cfg.Recon.Enabled {
			dim.Println("  ⏭️  Skipping reconnaissance phase (disabled in config)")
		} else {
			dim.Println("  ⏭️  Skipping reconnaissance phase (--skip-recon)")
		}
		subdomains := make([]string, 0)
		if !offlineImport && cfg.Scanning.Enabled {
			subdomains = append(subdomains, targetDomain)
		}
		reconResults = &recon.Results{
			Subdomains: subdomains,
			URLs:       make([]string, 0),
			Endpoints:  make([]string, 0),
			IPs:        make([]string, 0),
			JSFiles:    make([]recon.JSFile, 0),
		}
		fmt.Println()
	} else {
		printPhaseHeader("1", "RECONNAISSANCE", "📡")
		phaseStart = time.Now()

		reconEngine := recon.NewEngine(cfg, log)
		var err2 error
		reconResults, err2 = reconEngine.Run(ctx)
		if err2 != nil {
			return fmt.Errorf("reconnaissance failed: %w", err2)
		}

		reconDuration := time.Since(phaseStart)
		green.Printf("  ✅ Completed in %s\n", reconDuration.Round(time.Second))
		fmt.Printf("  ├── 🌐 Subdomains: %s\n", white.Sprintf("%d", len(reconResults.Subdomains)))
		fmt.Printf("  ├── 🔗 URLs:       %s\n", white.Sprintf("%d", len(reconResults.URLs)))
		fmt.Printf("  ├── 📍 Endpoints:  %s\n", white.Sprintf("%d", len(reconResults.Endpoints)))
		fmt.Printf("  └── 📜 JS Files:   %s\n", white.Sprintf("%d", len(reconResults.JSFiles)))

		// Print found subdomains if verbose
		if verbose && len(reconResults.Subdomains) > 0 {
			fmt.Println()
			yellow.Println("  📋 Sample Subdomains:")
			limit := 15
			if len(reconResults.Subdomains) < limit {
				limit = len(reconResults.Subdomains)
			}
			for i := 0; i < limit; i++ {
				dim.Printf("     %2d. ", i+1)
				fmt.Printf("%s\n", reconResults.Subdomains[i])
			}
			if len(reconResults.Subdomains) > limit {
				dim.Printf("     ... and %d more\n", len(reconResults.Subdomains)-limit)
			}
		}
		fmt.Println()
	}

	// ═══════════════════════════════════════
	// Phase 2: Vulnerability Scanning
	// ═══════════════════════════════════════
	var scanResults *scanner.Results
	var critical, high, medium, low, info int
	var displayFindings []scanner.Finding

	if skipScan || jsOnly || offlineImport || !cfg.Scanning.Enabled {
		if offlineImport {
			dim.Println("  ⏭️  Skipping active scans (--nmap-xml: offline import mode)")
		} else if jsOnly {
			dim.Println("  ⏭️  Skipping vulnerability scanning (--js-only: recon done, JS analysis next)")
		} else if !cfg.Scanning.Enabled {
			dim.Println("  ⏭️  Skipping vulnerability scanning (disabled in config)")
		} else {
			dim.Println("  ⏭️  Skipping vulnerability scanning (--skip-scan)")
		}
		scanResults = &scanner.Results{
			Findings: make([]scanner.Finding, 0),
		}
		fmt.Println()
	} else {
		printPhaseHeader("2", "VULNERABILITY SCANNING", "🔍")
		cyan.Println("  🎯 Executing deep vulnerability scan with multiple tools")
		yellow.Println("  ⏳ This phase may take several minutes - please be patient")
		phaseStart = time.Now()

		scanEngine := scanner.NewEngine(cfg, log)
		var err2 error
		scanResults, err2 = scanEngine.Run(ctx, reconResults)
		if err2 != nil {
			return fmt.Errorf("scanning failed: %w", err2)
		}

		scanDuration := time.Since(phaseStart)
		critical, high, medium, low, info = countBySeverity(scanResults.Findings)

		// Filter findings for display (hide "info" severity)
		for _, f := range scanResults.Findings {
			if f.Severity != "info" {
				displayFindings = append(displayFindings, f)
			}
		}

		green.Printf("  ✅ Scan completed successfully in %s\n", scanDuration.Round(time.Second))
		white.Printf("  📊 Actionable Findings: ")
		cyan.Printf("%d vulnerabilities (low/medium/high/critical)\n", len(displayFindings))
		if info > 0 {
			dim.Printf("  ℹ️  %d informational findings hidden from display\n", info)
		}
	}
	fmt.Println()

	if offlineImport {
		importedFindings, err := scanner.ImportNmapXML(nmapXMLFile, cfg.Target.Domains)
		if err != nil {
			return fmt.Errorf("failed to import Nmap XML: %w", err)
		}
		scanResults.Findings = append(scanResults.Findings, importedFindings...)
		critical, high, medium, low, info = countBySeverity(scanResults.Findings)
		if len(cfg.Reporting.SeverityFilter) == 0 {
			cfg.Reporting.SeverityFilter = []string{"critical", "high", "medium", "low", "info"}
		}
		log.Infof("Imported %d in-scope open-port findings from Nmap XML", len(importedFindings))
	}

	// Show findings details (only actionable ones)
	if len(displayFindings) > 0 {
		white.Println("  ┌─────────────────────────────────────────────┐")
		white.Printf("  │")
		cyan.Printf("  📊 Severity Distribution (Actionable)")
		fmt.Print("       ")
		white.Println("│")
		white.Println("  ├─────────────────────────────────────────────┤")
		if critical > 0 {
			white.Printf("  │  ")
			red.Printf("🔴 CRITICAL")
			fmt.Printf("  → ")
			red.Printf("%-3d", critical)
			fmt.Print(" vulnerabilities         ")
			white.Println("│")
		}
		if high > 0 {
			white.Printf("  │  ")
			color.New(color.FgHiRed).Printf("🟠 HIGH")
			fmt.Printf("      → ")
			color.New(color.FgHiRed).Printf("%-3d", high)
			fmt.Print(" vulnerabilities         ")
			white.Println("│")
		}
		if medium > 0 {
			white.Printf("  │  ")
			yellow.Printf("🟡 MEDIUM")
			fmt.Printf("    → ")
			yellow.Printf("%-3d", medium)
			fmt.Print(" vulnerabilities         ")
			white.Println("│")
		}
		if low > 0 {
			white.Printf("  │  ")
			green.Printf("🟢 LOW")
			fmt.Printf("       → ")
			green.Printf("%-3d", low)
			fmt.Print(" vulnerabilities         ")
			white.Println("│")
		}
		white.Println("  └─────────────────────────────────────────────┘")

		// Print individual findings (only actionable ones)
		fmt.Println()
		white.Printf("  ")
		cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		white.Printf("  ")
		yellow.Println("🔍 DETAILED VULNERABILITY REPORT (Actionable Only)")
		white.Printf("  ")
		cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println()
		for i, f := range displayFindings {
			sevColor := dim
			sevIcon := "ℹ️ "
			sevLabel := "INFO"
			switch f.Severity {
			case "critical":
				sevColor = red
				sevIcon = "🔴"
				sevLabel = "CRITICAL"
			case "high":
				sevColor = color.New(color.FgHiRed)
				sevIcon = "🟠"
				sevLabel = "HIGH"
			case "medium":
				sevColor = yellow
				sevIcon = "🟡"
				sevLabel = "MEDIUM"
			case "low":
				sevColor = green
				sevIcon = "🟢"
				sevLabel = "LOW"
			}

			white.Printf("  [%d/%d] ", i+1, len(displayFindings))
			sevColor.Printf("%s %s", sevIcon, sevLabel)
			fmt.Println()
			white.Printf("  └─ ")
			cyan.Printf("Title: ")
			white.Printf("%s\n", f.Title)
			if f.Target != "" {
				white.Printf("     ")
				cyan.Printf("Target: ")
				dim.Printf("%s\n", f.Target)
			}
			if f.URL != "" {
				white.Printf("     ")
				cyan.Printf("URL: ")
				dim.Printf("%s\n", f.URL)
			}
			if f.Evidence != "" {
				evidenceTrunc := f.Evidence
				if len(evidenceTrunc) > 120 {
					evidenceTrunc = evidenceTrunc[:120] + "..."
				}
				white.Printf("     ")
				cyan.Printf("Evidence: ")
				dim.Printf("%s\n", evidenceTrunc)
			}
			if f.CVE != "" {
				white.Printf("     ")
				red.Printf("CVE: %s", f.CVE)
				fmt.Println()
			}
			if i < len(displayFindings)-1 {
				fmt.Println()
			}
		}
		fmt.Println()
		// Note about filtered info findings
		if info > 0 {
			dim.Printf("  💡 Note: %d informational findings were hidden from display\n", info)
			dim.Println("     (They're retained in the report)")
			fmt.Println()
		}
		white.Printf("  ")
		cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	}
	fmt.Println()

	// ═══════════════════════════════════════
	// Phase 2.5: JavaScript file analysis with local regex rules
	// ═══════════════════════════════════════
	if cfg.Analysis.JSAnalysis && len(reconResults.JSFiles) > 0 {
		printPhaseHeader("2.5", "JS FILE ANALYSIS (LOCAL RULES)", "📜")
		phaseStart = time.Now()

		// Convert recon.JSFile to analyzer-compatible struct
		jsInput := make([]struct {
			URL     string
			Content string
			Size    int
			Source  string
		}, len(reconResults.JSFiles))
		for i, js := range reconResults.JSFiles {
			jsInput[i] = struct {
				URL     string
				Content string
				Size    int
				Source  string
			}{
				URL:     js.URL,
				Content: js.Content,
				Size:    js.Size,
				Source:  js.Source,
			}
		}

		// ── Step 1: Fast regex pre-scan (instant, no API calls) ──
		cyan.Printf("  🔎 Regex pre-scan on %d JS files...\n", len(reconResults.JSFiles))
		regexFindings := analyzer.ScanJSWithRegex(jsInput)
		if len(regexFindings) > 0 {
			green.Printf("  ├── ✅ Regex: found %d patterns\n", len(regexFindings))
			for _, rf := range regexFindings {
				sevColor := dim
				sevIcon := "ℹ️ "
				switch rf.Severity {
				case "critical":
					sevColor = red
					sevIcon = "🔴"
				case "high":
					sevColor = color.New(color.FgHiRed)
					sevIcon = "🟠"
				case "medium":
					sevColor = yellow
					sevIcon = "🟡"
				case "low":
					sevColor = green
					sevIcon = "🟢"
				}
				sevColor.Printf("     %s [%s] ", sevIcon, strings.ToUpper(rf.Severity))
				white.Printf("%s\n", rf.Title)
				if rf.Evidence != "" {
					evidenceTrunc := rf.Evidence
					if len(evidenceTrunc) > 80 {
						evidenceTrunc = evidenceTrunc[:80] + "..."
					}
					dim.Printf("        Value: %s\n", evidenceTrunc)
				}
			}
		} else {
			dim.Println("  ├── 🔎 Regex: no patterns detected")
		}

		cyan.Printf("  📁 Applying deterministic rules to %d JS files...\n", len(reconResults.JSFiles))

		jsDuration := time.Since(phaseStart)
		green.Printf("  ✅ Completed in %s\n", jsDuration.Round(time.Second))

		if len(regexFindings) > 0 {
			fmt.Printf("  └── 🔍 Rule-based JS findings: %s\n", white.Sprintf("%d", len(regexFindings)))
			fmt.Println()
			yellow.Println("  📋 Rule-based JS Analysis Results:")
			for _, finding := range regexFindings {
				dim.Printf("     [%s] %s\n", strings.ToUpper(finding.Severity), finding.Title)
			}
			scanResults.Findings = append(scanResults.Findings, regexFindings...)
			critical, high, medium, low, info = countBySeverity(scanResults.Findings)
		} else {
			dim.Println("  └── No matching JS patterns found")
		}
	} else if len(reconResults.JSFiles) == 0 {
		dim.Println("  ⏭️  JS Analysis: no JS files found during recon")
	}
	fmt.Println()

	// ═══════════════════════════════════════
	// Phase 3: Deterministic local analysis
	// ═══════════════════════════════════════
	printPhaseHeader("3", "RULE-BASED ANALYSIS", "🧭")
	phaseStart = time.Now()

	analyzerEngine := analyzer.NewEngine(cfg, log)
	analysisResults, err := analyzerEngine.Analyze(ctx, scanResults)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	analysisDuration := time.Since(phaseStart)
	green.Printf("  ✅ Completed in %s\n", analysisDuration.Round(time.Second))
	fmt.Printf("  ├── ✓ Rule-assessed:   %s\n", white.Sprintf("%d", len(analysisResults.ValidatedFindings)))
	fmt.Printf("  └── ✗ Discarded:       %s\n", white.Sprintf("%d", len(analysisResults.FalsePositives)))
	fmt.Println()

	// ═══════════════════════════════════════
	// Phase 4: Reporting
	// ═══════════════════════════════════════
	printPhaseHeader("4", "REPORT GENERATION", "📝")
	phaseStart = time.Now()

	reportGen := reporter.NewGenerator(cfg, log)
	reportPath, err := reportGen.Generate(reconResults, scanResults, analysisResults)
	if err != nil {
		return fmt.Errorf("report generation failed: %w", err)
	}

	reportDuration := time.Since(phaseStart)
	green.Printf("  ✅ Completed in %s\n", reportDuration.Round(time.Second))
	fmt.Printf("  └── 📄 Report: %s\n", cyan.Sprintf("%s", reportPath))
	fmt.Println()

	duration := time.Since(startTime)

	// Print final summary
	printSummary(duration, critical, high, medium, low, info, reportPath,
		len(reconResults.Subdomains), len(scanResults.Findings),
		len(analysisResults.ValidatedFindings))

	return nil
}

// checkTools validates required external tools for the enabled phases.
// Logs warnings for optional tools and fatals for required ones.
func checkTools(log interface{ Warnf(string, ...interface{}) }, cfg *config.Config, runRecon, runScan bool) {
	type tool struct {
		name     string
		check    bool
		required bool
		install  string
	}
	tools := []tool{
		{"subfinder", runRecon && cfg.Recon.Tools.Subfinder, runRecon && cfg.Recon.Tools.Subfinder, "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
		{"httpx", runScan && cfg.Scanning.Tools.Httpx.Enabled, runScan && cfg.Scanning.Tools.Httpx.Enabled, "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"},
		{"nuclei", runScan && (cfg.Scanning.Tools.Nuclei.Enabled || cfg.Scanning.Tools.SQLMap.Enabled), runScan && (cfg.Scanning.Tools.Nuclei.Enabled || cfg.Scanning.Tools.SQLMap.Enabled), "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
		// Optional but highly recommended
		{"katana", true, false, "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
		{"assetfinder", true, false, "go install github.com/tomnomnom/assetfinder@latest"},
		{"dalfox", true, false, "go install github.com/hahwul/dalfox/v2@latest"},
		{"ffuf", true, false, "go install github.com/ffuf/ffuf/v2@latest"},
		{"nmap", true, false, "apt install nmap"},
		{"arjun", true, false, "pip3 install arjun"},
	}

	missing := []string{}
	for _, t := range tools {
		if !t.check {
			continue
		}
		if _, err := exec.LookPath(t.name); err != nil {
			if t.required {
				missing = append(missing, fmt.Sprintf("  ❌ REQUIRED: %-12s → install: %s", t.name, t.install))
			} else {
				log.Warnf("Optional tool not found: %-10s (install: %s)", t.name, t.install)
			}
		}
	}

	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "\n⚠️  Missing required tools:\n")
		for _, m := range missing {
			fmt.Fprintf(os.Stderr, "%s\n", m)
		}
		fmt.Fprintf(os.Stderr, "\nInstall missing tools and re-run.\n\n")
		os.Exit(1)
	}
}

// validateDomain checks that the domain only contains valid characters
// to prevent command injection via user-supplied input passed to exec.Command
var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$`)

func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain too long (max 253 characters)")
	}
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("domain contains invalid characters — only alphanumeric, dots and hyphens allowed")
	}
	// Prevent localhost/internal targets accidentally
	lowered := strings.ToLower(domain)
	blocked := []string{"localhost", "127.0.0.1", "0.0.0.0", "::1"}
	for _, b := range blocked {
		if lowered == b {
			return fmt.Errorf("target '%s' is not a valid external domain", domain)
		}
	}
	return nil
}

func countBySeverity(findings []scanner.Finding) (int, int, int, int, int) {
	var critical, high, medium, low, info int
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		case "info":
			info++
		}
	}
	return critical, high, medium, low, info
}

func printPhaseHeader(num, title, icon string) {
	c := color.New(color.FgCyan, color.Bold)
	c.Printf("  ╔══════════════════════════════════════════════╗\n")
	c.Printf("  ║  %s Phase %s: %-32s║\n", icon, num, title)
	c.Printf("  ╚══════════════════════════════════════════════╝\n")
}

func printBanner() {
	fmt.Println(color.CyanString(banner()))
	fmt.Printf("  LinkedIn: %s\n", "https://www.linkedin.com/in/raj-prince-kumar-6478b2246/")
}

func banner() string {
	return `
╔══════════════════════════════════════════════════════════╗
║     BugBasket - Rule-Based Bug Bounty CLI                ║
║     Authorized Security Testing & Analysis               ║
╚══════════════════════════════════════════════════════════╝
`
}

func printSummary(duration time.Duration, critical, high, medium, low, info int,
	reportPath string, subdomains, totalFindings, validated int) {

	total := critical + high + medium + low + info

	bold := color.New(color.FgWhite, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	dim := color.New(color.FgHiBlack)

	cyan.Println("  ╔════════════════════════════════════════════════════╗")
	cyan.Println("  ║         🎯 BUGBASKET SCAN COMPLETED               ║")
	cyan.Println("  ╠════════════════════════════════════════════════════╣")
	cyan.Print("  ║")
	fmt.Printf("  ⏱️  Scan Duration:     %-26s", duration.Round(time.Second))
	cyan.Println("║")
	cyan.Print("  ║")
	fmt.Printf("  🌐 Subdomains:        %-26d", subdomains)
	cyan.Println("║")
	cyan.Print("  ║")
	fmt.Printf("  🔎 Vulnerabilities:   %-26d", totalFindings)
	cyan.Println("║")
	cyan.Print("  ║")
	fmt.Printf("  ✓  Rule-Assessed:     %-26d", validated)
	cyan.Println("║")
	cyan.Println("  ╠════════════════════════════════════════════════════╣")
	cyan.Print("  ║")
	bold.Print("  📊 Severity Distribution:                      ")
	cyan.Println("║")

	// Only show actionable severities (hide info)
	severities := []struct {
		icon  string
		name  string
		count int
		c     *color.Color
	}{
		{"🔴", "Critical", critical, red},
		{"🟠", "High", high, color.New(color.FgHiRed)},
		{"🟡", "Medium", medium, yellow},
		{"🟢", "Low", low, green},
	}

	for _, s := range severities {
		cyan.Print("  ║")
		if s.count > 0 {
			s.c.Printf("     %s %-10s → %-5d", s.icon, s.name, s.count)
		} else {
			fmt.Printf("     %s %-10s → %-5d", s.icon, s.name, s.count)
		}
		fmt.Print("                        ")
		cyan.Println("║")
	}

	// Show info count separately if exists
	if info > 0 {
		cyan.Print("  ║")
		dim.Printf("     ℹ️  Info (hidden) → %-5d", info)
		fmt.Print("                    ")
		cyan.Println("║")
	}

	cyan.Println("  ╠════════════════════════════════════════════════════╣")
	cyan.Print("  ║")
	fmt.Print("  📄 Report Location:                            ")
	cyan.Println("║")
	cyan.Print("  ║")
	bold.Printf("  %s", reportPath)
	// Pad to fill the box
	padding := 50 - len(reportPath)
	if padding > 0 {
		fmt.Print(strings.Repeat(" ", padding))
	}
	cyan.Println("║")
	cyan.Println("  ╠════════════════════════════════════════════════════╣")
	cyan.Print("  ║")
	dim.Print("  BugBasket | v2.1")
	cyan.Println("║")
	cyan.Println("  ╚════════════════════════════════════════════════════╝")

	fmt.Println()
	if total == 0 {
		green.Println("  ✅ SECURE: No vulnerabilities detected - Target appears secure")
	} else if critical > 0 {
		red.Printf("  🚨 URGENT: Found %d CRITICAL vulnerabilities - Immediate action required!\n", critical)
	} else if high > 0 {
		color.New(color.FgHiRed).Printf("  ⚠️  WARNING: Found %d HIGH severity issues - Review report immediately\n", high)
	} else if medium > 0 {
		yellow.Printf("  ⚡ ATTENTION: Found %d MEDIUM severity findings - Review recommended\n", medium)
	} else {
		green.Printf("  ℹ️  INFO: Found %d low-severity findings - Review when convenient\n", total)
	}
	fmt.Println()
	cyan.Println("  📌 Thank you for using BugBasket!")
	dim.Println("  🐦 Follow @A_cyb3r on Twitter for updates")
	fmt.Println()
}
