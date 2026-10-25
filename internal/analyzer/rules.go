package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
	"github.com/Btr4k/bugbounty-agent/internal/scanner"
)

type RuleAnalyzer struct {
	log *logger.Logger
}

type Analysis struct {
	ValidatedFindings  []ValidatedFinding
	FalsePositives     []ValidatedFinding
	ValidatedCount     int
	FalsePositiveCount int
	Stats              Statistics
	TopFindings        []ValidatedFinding
	Summary            string
	Recommendations    []string
	Timestamp          time.Time
}

type ValidatedFinding struct {
	scanner.Finding
	Retained         bool    `json:"retained"`
	Confidence       float64 `json:"confidence"`
	RuleAnalysis     string  `json:"rule_analysis"`
	ImpactAssessment string  `json:"impact_assessment,omitempty"`
	Remediation      string  `json:"remediation,omitempty"`
	ProofOfConcept   string  `json:"proof_of_concept,omitempty"`
}

type Statistics struct {
	Total          int
	Critical       int
	High           int
	Medium         int
	Low            int
	Info           int
	Validated      int
	FalsePositives int
}

func NewEngine(_ *config.Config, log *logger.Logger) *RuleAnalyzer {
	return &RuleAnalyzer{log: log}
}

func (a *RuleAnalyzer) Analyze(ctx context.Context, scanResults *scanner.Results) (*Analysis, error) {
	analysis := &Analysis{
		ValidatedFindings: make([]ValidatedFinding, 0, len(scanResults.Findings)),
		FalsePositives:    make([]ValidatedFinding, 0),
		Recommendations:   make([]string, 0),
		Timestamp:         time.Now(),
	}

	for _, finding := range scanResults.Findings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		rule := PreValidateFinding(finding)
		confidence := 0.5
		review := "Rule-based review: retained scanner finding; not independently confirmed."
		if rule.Outcome == PreValidReject {
			review = "Rule-based review: likely false positive; retained because automated rules do not discard scanner findings. " + rule.Reason
			confidence = 1
		} else if rule.Outcome == PreValidDowngrade {
			finding.Severity = rule.NewSeverity
			finding.Description = strings.TrimSpace(finding.Description + "\n\n[Rule-based note] " + rule.Reason)
			review = "Rule-based review: severity adjusted by a deterministic rule. " + rule.Reason
			confidence = 1
		}

		analysis.ValidatedFindings = append(analysis.ValidatedFindings, ValidatedFinding{
			Finding:          finding,
			Retained:         true,
			Confidence:       confidence,
			RuleAnalysis:     review,
			ImpactAssessment: localImpactAssessment(finding),
			Remediation:      localRemediation(finding),
		})
	}

	a.calculateStatistics(analysis)
	analysis.TopFindings = a.getTopFindings(analysis.ValidatedFindings, 10)
	analysis.Summary = fmt.Sprintf("Rule-based analysis retained %d scanner findings; manually verify exploitability.", len(analysis.ValidatedFindings))
	analysis.Recommendations = a.generateLocalRecommendations(analysis)
	a.log.Infof("Rule-based analysis completed: %d findings retained", len(analysis.ValidatedFindings))
	return analysis, nil
}

func (a *RuleAnalyzer) calculateStatistics(analysis *Analysis) {
	analysis.Stats = Statistics{
		Total:     len(analysis.ValidatedFindings),
		Validated: len(analysis.ValidatedFindings),
	}
	for _, finding := range analysis.ValidatedFindings {
		switch strings.ToLower(finding.Severity) {
		case "critical":
			analysis.Stats.Critical++
		case "high":
			analysis.Stats.High++
		case "medium":
			analysis.Stats.Medium++
		case "low":
			analysis.Stats.Low++
		default:
			analysis.Stats.Info++
		}
	}
	analysis.ValidatedCount = analysis.Stats.Validated
	analysis.FalsePositiveCount = 0
}

func (a *RuleAnalyzer) getTopFindings(findings []ValidatedFinding, limit int) []ValidatedFinding {
	severityOrder := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
	sorted := append([]ValidatedFinding(nil), findings...)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			left := severityOrder[strings.ToLower(sorted[i].Severity)]
			right := severityOrder[strings.ToLower(sorted[j].Severity)]
			if right > left || (right == left && sorted[j].Confidence > sorted[i].Confidence) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	if len(sorted) > limit {
		return sorted[:limit]
	}
	return sorted
}

func (a *RuleAnalyzer) generateLocalRecommendations(analysis *Analysis) []string {
	recommendations := make([]string, 0)
	if analysis.Stats.Critical > 0 || analysis.Stats.High > 0 {
		recommendations = append(recommendations, "Review critical and high-severity findings and verify impact before remediation.")
	}
	if len(analysis.ValidatedFindings) > 0 {
		recommendations = append(recommendations, "Manually verify scanner evidence; rule-based assessments do not establish exploitability.")
	}
	return recommendations
}

func localImpactAssessment(finding scanner.Finding) string {
	switch strings.ToLower(finding.Severity) {
	case "critical", "high":
		return "Potentially significant security impact based on scanner severity; verify the supplied evidence and affected asset."
	case "medium":
		return "Potential security impact based on scanner classification; verify exploitability and affected data."
	case "low":
		return "Limited or conditional impact based on scanner classification; manual verification is recommended."
	default:
		return "Informational scanner observation; no exploitability conclusion was made."
	}
}

func localRemediation(finding scanner.Finding) string {
	switch strings.ToLower(finding.Type) {
	case "cors", "cors-misconfiguration":
		return "Allow only trusted origins and enable credentialed requests only where required."
	case "js-analysis":
		return "Verify the matched value. Revoke exposed credentials and move secrets to a trusted server-side store."
	case "sqli", "sql-injection":
		return "Use parameterized queries and validate inputs at the application boundary."
	case "xss":
		return "Contextually encode untrusted output and use safe DOM APIs."
	case "port-scan":
		return "Disable unnecessary services and restrict exposed ports to required sources."
	default:
		return "Review the scanner evidence and apply the vendor-recommended fix for the identified component."
	}
}

func (a *RuleAnalyzer) AnalyzeJSFiles(_ context.Context, jsFiles []struct {
	URL     string
	Content string
	Size    int
	Source  string
}) ([]scanner.Finding, error) {
	return ScanJSWithRegex(jsFiles), nil
}
