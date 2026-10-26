package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Target        TargetConfig        `yaml:"target" mapstructure:"target"`
	Recon         ReconConfig         `yaml:"recon" mapstructure:"recon"`
	Scanning      ScanningConfig      `yaml:"scanning" mapstructure:"scanning"`
	Analysis      AnalysisConfig      `yaml:"analysis" mapstructure:"analysis"`
	Reporting     ReportingConfig     `yaml:"reporting" mapstructure:"reporting"`
	Notifications NotificationsConfig `yaml:"notifications" mapstructure:"notifications"`
	Logging       LoggingConfig       `yaml:"logging" mapstructure:"logging"`
}

type TargetConfig struct {
	Domains            []string `yaml:"domains" mapstructure:"domains"`
	ExcludedSubdomains []string `yaml:"excluded_subdomains" mapstructure:"excluded_subdomains"`
	Scope              string   `yaml:"scope" mapstructure:"scope"`
}

type ReconConfig struct {
	Enabled        bool             `yaml:"enabled" mapstructure:"enabled"`
	Timeout        int              `yaml:"timeout" mapstructure:"timeout"`
	MaxSubdomains  int              `yaml:"max_subdomains" mapstructure:"max_subdomains"`
	MaxWaybackURLs int              `yaml:"max_wayback_urls" mapstructure:"max_wayback_urls"`
	Tools          ReconToolsConfig `yaml:"tools" mapstructure:"tools"`
}

type ReconToolsConfig struct {
	Subfinder        bool `yaml:"subfinder" mapstructure:"subfinder"`
	Amass            bool `yaml:"amass" mapstructure:"amass"`
	Assetfinder      bool `yaml:"assetfinder" mapstructure:"assetfinder"`
	CertTransparency bool `yaml:"cert_transparency" mapstructure:"cert_transparency"`
	GitHubDorking    bool `yaml:"github_dorking" mapstructure:"github_dorking"`
	Wayback          bool `yaml:"wayback" mapstructure:"wayback"`
	Katana           bool `yaml:"katana" mapstructure:"katana"`
}

type ScanningConfig struct {
	Enabled   bool                `yaml:"enabled" mapstructure:"enabled"`
	Threads   int                 `yaml:"threads" mapstructure:"threads"`
	Timeout   int                 `yaml:"timeout" mapstructure:"timeout"`
	RateLimit int                 `yaml:"rate_limit" mapstructure:"rate_limit"`
	Tools     ScanningToolsConfig `yaml:"tools" mapstructure:"tools"`
}

type ScanningToolsConfig struct {
	Nuclei NucleiConfig `yaml:"nuclei" mapstructure:"nuclei"`
	Httpx  HttpxConfig  `yaml:"httpx" mapstructure:"httpx"`
	Nmap   NmapConfig   `yaml:"nmap" mapstructure:"nmap"`
	Dalfox DalfoxConfig `yaml:"dalfox" mapstructure:"dalfox"`
	SQLMap SQLMapConfig `yaml:"sqlmap" mapstructure:"sqlmap"`
	Arjun  ArjunConfig  `yaml:"arjun" mapstructure:"arjun"`
	Ffuf   FfufConfig   `yaml:"ffuf" mapstructure:"ffuf"`
	CORS   CORSConfig   `yaml:"cors" mapstructure:"cors"`
}

type FfufConfig struct {
	Enabled       bool   `yaml:"enabled" mapstructure:"enabled"`
	WordlistPath  string `yaml:"wordlist_path" mapstructure:"wordlist_path"`
	MaxTargets    int    `yaml:"max_targets" mapstructure:"max_targets"`
}

type SQLMapConfig struct {
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
	MaxURLs int  `yaml:"max_urls" mapstructure:"max_urls"`
}

type ArjunConfig struct {
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
}

type CORSConfig struct {
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
}

type NucleiConfig struct {
	Enabled       bool     `yaml:"enabled" mapstructure:"enabled"`
	Severity      []string `yaml:"severity" mapstructure:"severity"`
	TemplatesPath string   `yaml:"templates_path" mapstructure:"templates_path"`
}

type HttpxConfig struct {
	Enabled         bool `yaml:"enabled" mapstructure:"enabled"`
	FollowRedirects bool `yaml:"follow_redirects" mapstructure:"follow_redirects"`
	StatusCode      bool `yaml:"status_code" mapstructure:"status_code"`
}

type NmapConfig struct {
	Enabled  bool   `yaml:"enabled" mapstructure:"enabled"`
	Ports    string `yaml:"ports" mapstructure:"ports"`
	FastScan bool   `yaml:"fast_scan" mapstructure:"fast_scan"`
}

type DalfoxConfig struct {
	Enabled       bool   `yaml:"enabled" mapstructure:"enabled"`
	BlindURL      string `yaml:"blind_url" mapstructure:"blind_url"`
	MaxURLs       int    `yaml:"max_urls" mapstructure:"max_urls"`
}

type AnalysisConfig struct {
	Enabled    bool `yaml:"enabled" mapstructure:"enabled"`
	JSAnalysis bool `yaml:"js_analysis" mapstructure:"js_analysis"`
}

type ReportingConfig struct {
	Format         string   `yaml:"format" mapstructure:"format"`
	Language       string   `yaml:"language" mapstructure:"language"`
	IncludePOC     bool     `yaml:"include_poc" mapstructure:"include_poc"`
	SeverityFilter []string `yaml:"severity_filter" mapstructure:"severity_filter"`
	OutputDir      string   `yaml:"output_dir" mapstructure:"output_dir"`
}

type NotificationsConfig struct {
	Enabled        bool   `yaml:"enabled" mapstructure:"enabled"`
	SlackWebhook   string `yaml:"slack_webhook" mapstructure:"slack_webhook"`
	DiscordWebhook string `yaml:"discord_webhook" mapstructure:"discord_webhook"`
}

type LoggingConfig struct {
	Level     string `yaml:"level" mapstructure:"level"`
	File      string `yaml:"file" mapstructure:"file"`
	MaxSizeMB int    `yaml:"max_size_mb" mapstructure:"max_size_mb"`
}

// loadEnvFile loads environment variables from .env file if it exists.
// Rules: system env vars take precedence over .env; within .env, last value wins.
func loadEnvFile() {
	file, err := os.Open(".env")
	if err != nil {
		return // .env file is optional
	}
	defer file.Close()

	// Collect all values first (last duplicate wins within .env)
	values := make(map[string]string)
	order := []string{}
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if !seen[key] {
				order = append(order, key)
				seen[key] = true
			}
			values[key] = value // last value wins
		}
	}

	// Set env vars — skip if already set by system environment
	for _, key := range order {
		if os.Getenv(key) == "" {
			os.Setenv(key, values[key])
		}
	}
}

// Load loads configuration from file
func Load(filename string) (*Config, error) {
	// Load .env file first
	loadEnvFile()

	// Set defaults
	viper.SetDefault("recon.timeout", 300)
	viper.SetDefault("recon.max_subdomains", 1000)
	viper.SetDefault("recon.max_wayback_urls", 10000)
	viper.SetDefault("scanning.threads", 50)
	viper.SetDefault("scanning.rate_limit", 100)
	viper.SetDefault("reporting.format", "markdown")
	viper.SetDefault("reporting.language", "ar")
	// Read config file
	viper.SetConfigFile(filename)
	viper.SetConfigType("yaml")

	// Enable environment variable override
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate after expanding optional environment variables.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Note: Target.Domains is NOT validated here because it is set from the CLI
	// flag (--target) in main.go AFTER config.Load() returns.

	if c.Recon.Timeout <= 0 {
		return fmt.Errorf("recon timeout must be positive")
	}

	if c.Scanning.Threads <= 0 {
		return fmt.Errorf("scanning threads must be positive")
	}

	return nil
}

// Save saves configuration to file
func (c *Config) Save(filename string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}
