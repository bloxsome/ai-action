package ai

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetermineSeverityLevel(t *testing.T) {
	assessor := &AdvancedRiskAssessor{}

	testCases := []struct {
		score    float64
		expected string
	}{
		{score: 0.0, expected: "MINIMAL"},
		{score: 2.5, expected: "LOW"},
		{score: 5.0, expected: "MEDIUM"},
		{score: 7.5, expected: "HIGH"},
		{score: 9.5, expected: "CRITICAL"},
		{score: 10.0, expected: "CRITICAL"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := assessor.determineSeverityLevel(tc.score)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestCalculateExploitability(t *testing.T) {
	assessor := &AdvancedRiskAssessor{}

	factors := []RiskFactor{
		{Name: "Input Validation", Score: 0.8, Weight: 0.15},
		{Name: "Authentication Security", Score: 0.7, Weight: 0.18},
		{Name: "Authorization Controls", Score: 0.6, Weight: 0.15},
		{Name: "Configuration Security", Score: 0.5, Weight: 0.10},
		{Name: "Data Protection", Score: 0.3, Weight: 0.12},
	}

	exploitability := assessor.calculateExploitability(factors)

	// Should be weighted average of relevant factors
	assert.Greater(t, exploitability, 0.0)
	assert.LessOrEqual(t, exploitability, 1.0)
	// With high input validation and auth scores, exploitability should be elevated
	assert.Greater(t, exploitability, 0.5)
}

func TestCalculateImpact(t *testing.T) {
	assessor := &AdvancedRiskAssessor{}

	factors := []RiskFactor{
		{Name: "Data Protection", Score: 0.9, Weight: 0.12},
		{Name: "Cryptographic Implementation", Score: 0.7, Weight: 0.12},
		{Name: "Authorization Controls", Score: 0.6, Weight: 0.15},
		{Name: "Dependency Security", Score: 0.5, Weight: 0.10},
	}

	impact := assessor.calculateImpact(factors)

	assert.Greater(t, impact, 0.0)
	assert.LessOrEqual(t, impact, 1.0)
	// With high data protection score, impact should be elevated
	assert.Greater(t, impact, 0.6)
}

func TestCalculateOverallRiskScore(t *testing.T) {
	assessor := &AdvancedRiskAssessor{}

	testCases := []struct {
		name           string
		exploitability float64
		impact         float64
		expectedMin    float64
		expectedMax    float64
	}{
		{
			name:           "Low risk",
			exploitability: 0.2,
			impact:         0.2,
			expectedMin:    0.0,
			expectedMax:    3.0,
		},
		{
			name:           "Medium risk",
			exploitability: 0.5,
			impact:         0.5,
			expectedMin:    3.0,
			expectedMax:    7.0,
		},
		{
			name:           "High risk",
			exploitability: 0.8,
			impact:         0.8,
			expectedMin:    6.0,
			expectedMax:    10.0,
		},
		{
			name:           "Critical risk",
			exploitability: 1.0,
			impact:         1.0,
			expectedMin:    8.0,
			expectedMax:    10.0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			score := assessor.calculateOverallRiskScore(tc.exploitability, tc.impact)

			assert.GreaterOrEqual(t, score, tc.expectedMin,
				"Score should be at least minimum expected")
			assert.LessOrEqual(t, score, tc.expectedMax,
				"Score should not exceed maximum expected")
			assert.GreaterOrEqual(t, score, 0.0, "Score should be non-negative")
			assert.LessOrEqual(t, score, 10.0, "Score should not exceed 10")
		})
	}
}

func TestCalculateOverallRiskScore_ZeroImpact(t *testing.T) {
	assessor := &AdvancedRiskAssessor{}

	score := assessor.calculateOverallRiskScore(0.8, 0.0)
	assert.Equal(t, 0.0, score, "Zero impact should result in zero score")
}

func TestScoreByKeywords(t *testing.T) {
	assessor := &AdvancedRiskAssessor{}

	testCases := []struct {
		name     string
		text     string
		keywords []string
		minScore float64
		maxScore float64
	}{
		{
			name:     "No matches",
			text:     "This is safe code with no issues",
			keywords: []string{"vulnerability", "exploit", "injection"},
			minScore: 0.0,
			maxScore: 0.0,
		},
		{
			name:     "Single keyword match",
			text:     "Found an authentication issue in the code",
			keywords: []string{"authentication"},
			minScore: 0.1,
			maxScore: 0.5,
		},
		{
			name:     "Multiple keyword matches",
			text:     "Critical authentication vulnerability with severe impact on password security",
			keywords: []string{"authentication", "password", "vulnerability"},
			minScore: 0.3,
			maxScore: 1.0,
		},
		{
			name:     "With severity context",
			text:     "Critical authentication failure detected in login system",
			keywords: []string{"authentication"},
			minScore: 0.3,
			maxScore: 1.0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			score := assessor.scoreByKeywords(strings.ToLower(tc.text), tc.keywords)

			assert.GreaterOrEqual(t, score, tc.minScore,
				"Score should be at least minimum expected")
			assert.LessOrEqual(t, score, tc.maxScore,
				"Score should not exceed maximum expected")
			assert.GreaterOrEqual(t, score, 0.0, "Score should be non-negative")
			assert.LessOrEqual(t, score, 1.0, "Score should not exceed 1.0")
		})
	}
}

func TestHeuristicScoring(t *testing.T) {
	assessor := &AdvancedRiskAssessor{}

	analysisText := `
	Found critical SQL injection vulnerability in authentication module.
	Password hashing uses weak MD5 algorithm.
	Missing input validation on user data.
	Authorization checks are bypassed in admin endpoints.
	Sensitive data exposure through error messages.
	Multiple vulnerable dependencies detected.
	Hardcoded credentials in configuration files.
	`

	factors := assessor.heuristicScoring(analysisText)

	assert.Len(t, factors, 8, "Should have all 8 risk factors")

	// Verify factors are scored
	for _, factor := range factors {
		assert.NotEmpty(t, factor.Name)
		assert.Greater(t, factor.Weight, 0.0)
		assert.GreaterOrEqual(t, factor.Score, 0.0)
		assert.LessOrEqual(t, factor.Score, 1.0)
	}

	// Verify specific high-risk factors have elevated scores
	factorScores := make(map[string]float64)
	for _, factor := range factors {
		factorScores[factor.Name] = factor.Score
	}

	assert.Greater(t, factorScores["Input Validation"], 0.3,
		"Input validation should show elevated risk")
	assert.Greater(t, factorScores["Authentication Security"], 0.3,
		"Authentication should show elevated risk")
}

func TestCalculateConfidence(t *testing.T) {
	assessor := &AdvancedRiskAssessor{}

	testCases := []struct {
		name        string
		analysisLen int
		fileCount   int
		minConf     float64
		maxConf     float64
	}{
		{
			name:        "Minimal analysis",
			analysisLen: 500,
			fileCount:   2,
			minConf:     0.5,
			maxConf:     0.7,
		},
		{
			name:        "Moderate analysis",
			analysisLen: 3000,
			fileCount:   7,
			minConf:     0.6,
			maxConf:     0.8,
		},
		{
			name:        "Comprehensive analysis",
			analysisLen: 8000,
			fileCount:   15,
			minConf:     0.7,
			maxConf:     0.95,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create analysis text with appropriate indicators
			analysis := strings.Repeat("Analysis details. ", tc.analysisLen/20)
			analysis += "Line 42 has issue. Recommendation: fix it. Remediation: apply patch."

			confidence := assessor.calculateConfidence(analysis, tc.fileCount)

			assert.GreaterOrEqual(t, confidence, tc.minConf,
				"Confidence should be at least minimum expected")
			assert.LessOrEqual(t, confidence, tc.maxConf,
				"Confidence should not exceed maximum expected")
			assert.LessOrEqual(t, confidence, 0.95,
				"Confidence should be capped at 0.95")
		})
	}
}

func TestParseInsights(t *testing.T) {
	assessor := &AdvancedRiskAssessor{}

	response := `
FINDINGS:
1. Critical SQL injection in user authentication module
2. Hardcoded API keys in configuration files
3. Missing CSRF protection on state-changing endpoints
4. Weak password hashing using MD5
5. Insufficient input validation on file uploads

RECOMMENDATIONS:
1. Implement parameterized queries for all database operations
2. Move secrets to environment variables or secret management system
3. Add CSRF tokens to all forms and validate on server
4. Upgrade to bcrypt or Argon2 for password hashing
5. Add file type and size validation with allowlist approach
`

	findings, recommendations := assessor.parseInsights(response)

	assert.Len(t, findings, 5, "Should extract 5 findings")
	assert.Len(t, recommendations, 5, "Should extract 5 recommendations")

	// Verify content
	assert.Contains(t, findings[0], "SQL injection")
	assert.Contains(t, findings[1], "Hardcoded API keys")
	assert.Contains(t, recommendations[0], "parameterized queries")
	assert.Contains(t, recommendations[1], "environment variables")
}

func TestParseInsights_MalformedResponse(t *testing.T) {
	assessor := &AdvancedRiskAssessor{}

	response := "This is a malformed response without proper sections"

	findings, recommendations := assessor.parseInsights(response)

	// Should return default values
	assert.NotEmpty(t, findings, "Should have default findings")
	assert.NotEmpty(t, recommendations, "Should have default recommendations")
}

func TestFormatRiskReport(t *testing.T) {
	assessment := &RiskAssessment{
		OverallScore:    7.5,
		OverallSeverity: "HIGH",
		RiskFactors: []RiskFactor{
			{
				Name:        "Authentication Security",
				Weight:      0.18,
				Score:       0.8,
				Description: "Multiple authentication vulnerabilities detected",
			},
			{
				Name:        "Input Validation",
				Weight:      0.15,
				Score:       0.7,
				Description: "Insufficient input sanitization",
			},
		},
		KeyFindings: []string{
			"SQL injection in login endpoint",
			"Hardcoded credentials detected",
		},
		TopRecommendations: []string{
			"Implement parameterized queries",
			"Use environment variables for secrets",
		},
		ExploitabilityScore: 0.75,
		ImpactScore:         0.80,
		ConfidenceLevel:     0.85,
	}

	report := FormatRiskReport(assessment)

	// Verify report structure
	assert.Contains(t, report, "Comprehensive Risk Assessment")
	assert.Contains(t, report, "7.5/10.0")
	assert.Contains(t, report, "HIGH")
	assert.Contains(t, report, "85%") // Confidence

	// Verify risk factors
	assert.Contains(t, report, "Authentication Security")
	assert.Contains(t, report, "Input Validation")
	assert.Contains(t, report, "0.80/1.0")
	assert.Contains(t, report, "0.70/1.0")

	// Verify findings and recommendations
	assert.Contains(t, report, "SQL injection")
	assert.Contains(t, report, "parameterized queries")
}

func TestGetSeverityIndicator(t *testing.T) {
	testCases := []struct {
		severity string
		expected string
	}{
		{severity: "CRITICAL", expected: "🚨"},
		{severity: "HIGH", expected: "🔴"},
		{severity: "MEDIUM", expected: "🟠"},
		{severity: "LOW", expected: "🟡"},
		{severity: "MINIMAL", expected: "🟢"},
		{severity: "UNKNOWN", expected: "⚪"},
	}

	for _, tc := range testCases {
		t.Run(tc.severity, func(t *testing.T) {
			indicator := getSeverityIndicator(tc.severity)
			assert.Contains(t, indicator, tc.expected)
			assert.NotEmpty(t, indicator)
		})
	}
}

func TestGetScoreIndicator(t *testing.T) {
	testCases := []struct {
		score    float64
		expected string
	}{
		{score: 0.9, expected: "🚨"},
		{score: 0.7, expected: "🔴"},
		{score: 0.5, expected: "🟠"},
		{score: 0.3, expected: "🟡"},
		{score: 0.1, expected: "🟢"},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			indicator := getScoreIndicator(tc.score)
			assert.Equal(t, tc.expected, indicator)
		})
	}
}

func TestParseAndApplyScores(t *testing.T) {
	assessor := &AdvancedRiskAssessor{}

	factors := []RiskFactor{
		{Name: "Authentication Security", Weight: 0.18},
		{Name: "Input Validation", Weight: 0.15},
		{Name: "Cryptographic Implementation", Weight: 0.12},
	}

	response := `
Authentication Security: 0.75 - Multiple weak points identified
Input Validation: 0.60 - Some validation gaps present
Cryptographic Implementation: 0.45 - Generally secure with minor issues
`

	assessor.parseAndApplyScores(&factors, response)

	assert.Equal(t, 0.75, factors[0].Score)
	assert.Contains(t, factors[0].Description, "weak points")

	assert.Equal(t, 0.60, factors[1].Score)
	assert.Contains(t, factors[1].Description, "validation gaps")

	assert.Equal(t, 0.45, factors[2].Score)
	assert.Contains(t, factors[2].Description, "minor issues")
}

func TestRiskFactorWeightsSum(t *testing.T) {
	assessor := &AdvancedRiskAssessor{}
	factors := assessor.heuristicScoring("")

	totalWeight := 0.0
	for _, factor := range factors {
		totalWeight += factor.Weight
	}

	// Weights should approximately sum to 1.0 (allowing small floating point errors)
	assert.InDelta(t, 1.0, totalWeight, 0.01,
		"Risk factor weights should sum to approximately 1.0")
}

func BenchmarkCalculateOverallRiskScore(b *testing.B) {
	assessor := &AdvancedRiskAssessor{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = assessor.calculateOverallRiskScore(0.7, 0.8)
	}
}

func BenchmarkHeuristicScoring(b *testing.B) {
	assessor := &AdvancedRiskAssessor{}

	analysisText := strings.Repeat(`
	Found critical SQL injection vulnerability in authentication module.
	Password hashing uses weak MD5 algorithm.
	Missing input validation on user data.
	`, 10)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = assessor.heuristicScoring(analysisText)
	}
}
