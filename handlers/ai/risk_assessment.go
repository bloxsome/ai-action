package ai

import (
	"context"
	"fmt"
	"math"
	"strings"
)

// RiskFactor represents a security risk dimension
type RiskFactor struct {
	Name        string
	Weight      float64
	Score       float64 // 0.0 to 1.0
	Description string
}

// RiskAssessment provides comprehensive risk scoring
type RiskAssessment struct {
	OverallScore      float64      // 0.0 to 10.0
	OverallSeverity   string       // LOW, MEDIUM, HIGH, CRITICAL
	RiskFactors       []RiskFactor
	KeyFindings       []string
	TopRecommendations []string
	ExploitabilityScore float64    // 0.0 to 1.0
	ImpactScore       float64      // 0.0 to 1.0
	ConfidenceLevel   float64      // 0.0 to 1.0
}

// AdvancedRiskAssessor provides ML-enhanced risk assessment
type AdvancedRiskAssessor struct {
	aiHandler *AIHandler
}

// NewAdvancedRiskAssessor creates a new risk assessor
func NewAdvancedRiskAssessor(aiHandler *AIHandler) *AdvancedRiskAssessor {
	return &AdvancedRiskAssessor{
		aiHandler: aiHandler,
	}
}

// AssessSecurityRisk performs comprehensive risk assessment
func (ara *AdvancedRiskAssessor) AssessSecurityRisk(ctx context.Context, analysisResult string, files []FileContext) (*RiskAssessment, error) {
	// Calculate risk factors
	riskFactors, err := ara.calculateRiskFactors(ctx, analysisResult, files)
	if err != nil {
		return nil, err
	}

	// Calculate overall scores
	exploitability := ara.calculateExploitability(riskFactors)
	impact := ara.calculateImpact(riskFactors)
	overallScore := ara.calculateOverallRiskScore(exploitability, impact)

	// Determine severity
	severity := ara.determineSeverityLevel(overallScore)

	// Extract key findings and recommendations
	keyFindings, recommendations, err := ara.extractKeyInsights(ctx, analysisResult)
	if err != nil {
		return nil, err
	}

	// Calculate confidence based on analysis depth
	confidence := ara.calculateConfidence(analysisResult, len(files))

	return &RiskAssessment{
		OverallScore:        overallScore,
		OverallSeverity:     severity,
		RiskFactors:         riskFactors,
		KeyFindings:         keyFindings,
		TopRecommendations:  recommendations,
		ExploitabilityScore: exploitability,
		ImpactScore:         impact,
		ConfidenceLevel:     confidence,
	}, nil
}

// calculateRiskFactors identifies and scores individual risk dimensions
func (ara *AdvancedRiskAssessor) calculateRiskFactors(ctx context.Context, analysisResult string, files []FileContext) ([]RiskFactor, error) {
	factors := []RiskFactor{
		{Name: "Authentication Security", Weight: 0.18},
		{Name: "Input Validation", Weight: 0.15},
		{Name: "Cryptographic Implementation", Weight: 0.12},
		{Name: "Authorization Controls", Weight: 0.15},
		{Name: "Data Protection", Weight: 0.12},
		{Name: "Error Handling", Weight: 0.08},
		{Name: "Dependency Security", Weight: 0.10},
		{Name: "Configuration Security", Weight: 0.10},
	}

	// Use AI to score each factor
	prompt := fmt.Sprintf(`Analyze the following security assessment and score each risk dimension from 0.0 (secure) to 1.0 (critical risk):

Security Analysis:
%s

For each of these risk factors, provide a score (0.0-1.0) and brief justification:
1. Authentication Security
2. Input Validation
3. Cryptographic Implementation
4. Authorization Controls
5. Data Protection
6. Error Handling
7. Dependency Security
8. Configuration Security

Format your response as:
Factor: score (0.0-1.0) - Brief justification

Be strict and realistic in scoring. A score of 0.5+ indicates significant issues.`, analysisResult)

	response, err := ara.aiHandler.Call(ctx, prompt)
	if err != nil {
		// Fallback to heuristic scoring
		return ara.heuristicScoring(analysisResult), nil
	}

	// Parse AI response to extract scores
	ara.parseAndApplyScores(&factors, response)

	return factors, nil
}

// parseAndApplyScores extracts scores from AI response
func (ara *AdvancedRiskAssessor) parseAndApplyScores(factors *[]RiskFactor, response string) {
	lines := strings.Split(response, "\n")

	factorIdx := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Extract score pattern like "0.7" or "0.75"
		for i := 0; i < len(line)-2; i++ {
			if line[i] >= '0' && line[i] <= '1' && line[i+1] == '.' {
				// Found potential score
				scoreStr := line[i:min(i+4, len(line))]
				var score float64
				if _, err := fmt.Sscanf(scoreStr, "%f", &score); err == nil {
					if score >= 0.0 && score <= 1.0 && factorIdx < len(*factors) {
						(*factors)[factorIdx].Score = score
						// Extract description after the score
						descStart := strings.Index(line, "-")
						if descStart > 0 && descStart < len(line)-1 {
							(*factors)[factorIdx].Description = strings.TrimSpace(line[descStart+1:])
						}
						factorIdx++
						break
					}
				}
			}
		}
	}
}

// heuristicScoring provides fallback scoring based on keyword analysis
func (ara *AdvancedRiskAssessor) heuristicScoring(analysisResult string) []RiskFactor {
	lower := strings.ToLower(analysisResult)

	return []RiskFactor{
		{
			Name:   "Authentication Security",
			Weight: 0.18,
			Score:  ara.scoreByKeywords(lower, []string{"authentication", "password", "login", "session", "jwt", "token"}),
		},
		{
			Name:   "Input Validation",
			Weight: 0.15,
			Score:  ara.scoreByKeywords(lower, []string{"injection", "xss", "validation", "sanitiz", "input"}),
		},
		{
			Name:   "Cryptographic Implementation",
			Weight: 0.12,
			Score:  ara.scoreByKeywords(lower, []string{"crypto", "encryption", "hash", "md5", "sha1", "weak"}),
		},
		{
			Name:   "Authorization Controls",
			Weight: 0.15,
			Score:  ara.scoreByKeywords(lower, []string{"authorization", "permission", "access control", "rbac", "privilege"}),
		},
		{
			Name:   "Data Protection",
			Weight: 0.12,
			Score:  ara.scoreByKeywords(lower, []string{"data", "sensitive", "pii", "exposure", "leak"}),
		},
		{
			Name:   "Error Handling",
			Weight: 0.08,
			Score:  ara.scoreByKeywords(lower, []string{"error", "exception", "disclosure", "stack trace"}),
		},
		{
			Name:   "Dependency Security",
			Weight: 0.10,
			Score:  ara.scoreByKeywords(lower, []string{"dependency", "library", "package", "vulnerable", "outdated"}),
		},
		{
			Name:   "Configuration Security",
			Weight: 0.10,
			Score:  ara.scoreByKeywords(lower, []string{"configuration", "config", "secret", "credential", "hardcoded"}),
		},
	}
}

// scoreByKeywords calculates score based on keyword frequency and severity indicators
func (ara *AdvancedRiskAssessor) scoreByKeywords(text string, keywords []string) float64 {
	score := 0.0
	severityMultipliers := map[string]float64{
		"critical": 1.0,
		"severe":   0.9,
		"high":     0.8,
		"major":    0.7,
		"medium":   0.5,
		"minor":    0.3,
		"low":      0.2,
	}

	for _, keyword := range keywords {
		count := strings.Count(text, keyword)
		if count > 0 {
			score += float64(count) * 0.1

			// Check for severity context around keyword
			for severity, multiplier := range severityMultipliers {
				if strings.Contains(text, keyword+" "+severity) ||
				   strings.Contains(text, severity+" "+keyword) {
					score += 0.2 * multiplier
				}
			}
		}
	}

	// Normalize to 0.0-1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// calculateExploitability determines how easily vulnerabilities can be exploited
func (ara *AdvancedRiskAssessor) calculateExploitability(factors []RiskFactor) float64 {
	// Exploitability is heavily weighted by input validation and authentication
	exploitabilityFactors := map[string]float64{
		"Input Validation":      0.35,
		"Authentication Security": 0.30,
		"Authorization Controls":  0.20,
		"Configuration Security":  0.15,
	}

	score := 0.0
	for _, factor := range factors {
		if weight, exists := exploitabilityFactors[factor.Name]; exists {
			score += factor.Score * weight
		}
	}

	return score
}

// calculateImpact determines the potential impact of successful exploitation
func (ara *AdvancedRiskAssessor) calculateImpact(factors []RiskFactor) float64 {
	// Impact is about data protection, crypto, and business logic
	impactFactors := map[string]float64{
		"Data Protection":              0.35,
		"Cryptographic Implementation": 0.25,
		"Authorization Controls":       0.25,
		"Dependency Security":          0.15,
	}

	score := 0.0
	for _, factor := range factors {
		if weight, exists := impactFactors[factor.Name]; exists {
			score += factor.Score * weight
		}
	}

	return score
}

// calculateOverallRiskScore combines exploitability and impact using CVSS-like formula
func (ara *AdvancedRiskAssessor) calculateOverallRiskScore(exploitability, impact float64) float64 {
	// Modified CVSS formula scaled to 10
	if impact == 0 {
		return 0
	}

	// Base score formula
	impactSubScore := 1 - ((1 - impact) * (1 - 0.0)) // Simplified confidentiality/integrity/availability

	// Exploitability sub-score
	exploitSubScore := 8.22 * exploitability

	// Calculate final score
	if impactSubScore <= 0 {
		return 0
	}

	score := math.Min(1.08 * (impactSubScore + exploitSubScore), 10.0)

	// Ensure reasonable range
	if score < 0 {
		score = 0
	}
	if score > 10 {
		score = 10
	}

	return math.Round(score*10) / 10 // Round to 1 decimal
}

// determineSeverityLevel maps numeric score to severity category
func (ara *AdvancedRiskAssessor) determineSeverityLevel(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score >= 0.1:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

// extractKeyInsights uses AI to extract actionable insights
func (ara *AdvancedRiskAssessor) extractKeyInsights(ctx context.Context, analysisResult string) ([]string, []string, error) {
	prompt := fmt.Sprintf(`From the following security analysis, extract:

1. The top 5 most critical findings (concrete, specific issues)
2. The top 5 most important recommendations (actionable steps)

Security Analysis:
%s

Format your response as:
FINDINGS:
1. [specific finding]
2. [specific finding]
...

RECOMMENDATIONS:
1. [actionable step]
2. [actionable step]
...`, analysisResult)

	response, err := ara.aiHandler.Call(ctx, prompt)
	if err != nil {
		return []string{"Analysis parsing error"}, []string{"Review security analysis manually"}, nil
	}

	findings, recommendations := ara.parseInsights(response)
	return findings, recommendations, nil
}

// parseInsights extracts structured insights from AI response
func (ara *AdvancedRiskAssessor) parseInsights(response string) ([]string, []string) {
	var findings []string
	var recommendations []string

	lines := strings.Split(response, "\n")
	inFindings := false
	inRecommendations := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(strings.ToUpper(line), "FINDINGS") {
			inFindings = true
			inRecommendations = false
			continue
		} else if strings.HasPrefix(strings.ToUpper(line), "RECOMMENDATIONS") {
			inFindings = false
			inRecommendations = true
			continue
		}

		// Extract numbered items
		if len(line) > 2 && line[0] >= '1' && line[0] <= '9' && (line[1] == '.' || line[1] == ')') {
			item := strings.TrimSpace(line[2:])
			if item != "" {
				if inFindings {
					findings = append(findings, item)
				} else if inRecommendations {
					recommendations = append(recommendations, item)
				}
			}
		}
	}

	// Ensure we have at least something
	if len(findings) == 0 {
		findings = []string{"See full analysis for detailed findings"}
	}
	if len(recommendations) == 0 {
		recommendations = []string{"Review and address all identified vulnerabilities"}
	}

	return findings, recommendations
}

// calculateConfidence determines analysis confidence based on data quality
func (ara *AdvancedRiskAssessor) calculateConfidence(analysisResult string, fileCount int) float64 {
	confidence := 0.5 // Base confidence

	// More files analyzed = higher confidence
	if fileCount >= 10 {
		confidence += 0.2
	} else if fileCount >= 5 {
		confidence += 0.1
	}

	// Length and depth of analysis
	if len(analysisResult) > 5000 {
		confidence += 0.15
	} else if len(analysisResult) > 2000 {
		confidence += 0.10
	}

	// Check for detailed analysis indicators
	if strings.Contains(analysisResult, "Line ") || strings.Contains(analysisResult, "line ") {
		confidence += 0.05
	}
	if strings.Contains(analysisResult, "recommendation") {
		confidence += 0.05
	}
	if strings.Contains(analysisResult, "remediation") {
		confidence += 0.05
	}

	// Cap at 0.95 (never 100% confident)
	if confidence > 0.95 {
		confidence = 0.95
	}

	return confidence
}

// FormatRiskReport generates a comprehensive formatted risk report
func FormatRiskReport(assessment *RiskAssessment) string {
	var report strings.Builder

	// Overall Risk Summary
	report.WriteString("# 📊 Comprehensive Risk Assessment\n\n")
	report.WriteString(fmt.Sprintf("**Overall Risk Score**: %.1f/10.0 (%s)\n\n", assessment.OverallScore, assessment.OverallSeverity))
	report.WriteString(fmt.Sprintf("**Exploitability**: %.1f/10.0 | **Impact**: %.1f/10.0 | **Confidence**: %.0f%%\n\n",
		assessment.ExploitabilityScore*10, assessment.ImpactScore*10, assessment.ConfidenceLevel*100))

	// Risk Severity Indicator
	report.WriteString(getSeverityIndicator(assessment.OverallSeverity))
	report.WriteString("\n\n")

	// Risk Factors Breakdown
	report.WriteString("## 🔍 Risk Factor Analysis\n\n")
	for _, factor := range assessment.RiskFactors {
		scoreIndicator := getScoreIndicator(factor.Score)
		report.WriteString(fmt.Sprintf("### %s %s\n", scoreIndicator, factor.Name))
		report.WriteString(fmt.Sprintf("- **Score**: %.2f/1.0 (Weight: %.0f%%)\n", factor.Score, factor.Weight*100))
		if factor.Description != "" {
			report.WriteString(fmt.Sprintf("- **Assessment**: %s\n", factor.Description))
		}
		report.WriteString("\n")
	}

	// Key Findings
	if len(assessment.KeyFindings) > 0 {
		report.WriteString("## 🚨 Critical Findings\n\n")
		for i, finding := range assessment.KeyFindings {
			report.WriteString(fmt.Sprintf("%d. %s\n", i+1, finding))
		}
		report.WriteString("\n")
	}

	// Top Recommendations
	if len(assessment.TopRecommendations) > 0 {
		report.WriteString("## ✅ Priority Recommendations\n\n")
		for i, rec := range assessment.TopRecommendations {
			report.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
		report.WriteString("\n")
	}

	return report.String()
}

// getSeverityIndicator returns a visual indicator for severity level
func getSeverityIndicator(severity string) string {
	indicators := map[string]string{
		"CRITICAL": "🚨 **CRITICAL RISK** - Immediate action required. Severe vulnerabilities present significant security threats.",
		"HIGH":     "🔴 **HIGH RISK** - Urgent attention needed. Multiple serious security issues identified.",
		"MEDIUM":   "🟠 **MEDIUM RISK** - Security improvements recommended. Notable vulnerabilities should be addressed.",
		"LOW":      "🟡 **LOW RISK** - Minor security considerations. Review and improve when possible.",
		"MINIMAL":  "🟢 **MINIMAL RISK** - Good security posture. Continue following best practices.",
	}

	if indicator, exists := indicators[severity]; exists {
		return indicator
	}
	return "⚪ **UNKNOWN RISK** - Unable to determine risk level."
}

// getScoreIndicator returns an emoji indicator for a score
func getScoreIndicator(score float64) string {
	switch {
	case score >= 0.8:
		return "🚨"
	case score >= 0.6:
		return "🔴"
	case score >= 0.4:
		return "🟠"
	case score >= 0.2:
		return "🟡"
	default:
		return "🟢"
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
