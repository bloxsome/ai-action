package ai

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurityPatternMatcher_SQLInjection(t *testing.T) {
	matcher := NewSecurityPatternMatcher()

	testCases := []struct {
		name           string
		code           string
		shouldDetect   bool
		expectedPattern string
	}{
		{
			name:           "SQL injection with string concatenation",
			code:           `db.Exec("SELECT * FROM users WHERE id = " + userInput)`,
			shouldDetect:   true,
			expectedPattern: "SQL Injection",
		},
		{
			name:           "SQL injection with fmt.Sprintf",
			code:           `query := fmt.Sprintf("SELECT * FROM %s WHERE id = %s", table, id)`,
			shouldDetect:   true,
			expectedPattern: "SQL Injection",
		},
		{
			name:           "Safe parameterized query",
			code:           `db.Query("SELECT * FROM users WHERE id = ?", userInput)`,
			shouldDetect:   false,
			expectedPattern: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findings := matcher.ScanFileForPatterns("test.go", tc.code)

			if tc.shouldDetect {
				assert.NotEmpty(t, findings, "Expected to detect vulnerability")
				if len(findings) > 0 {
					assert.Equal(t, tc.expectedPattern, findings[0].Pattern)
					assert.Equal(t, "CRITICAL", findings[0].Severity)
				}
			} else {
				assert.Empty(t, findings, "Should not detect vulnerability in safe code")
			}
		})
	}
}

func TestSecurityPatternMatcher_HardcodedSecrets(t *testing.T) {
	matcher := NewSecurityPatternMatcher()

	testCases := []struct {
		name         string
		code         string
		shouldDetect bool
	}{
		{
			name:         "Hardcoded password",
			code:         `password := "SuperSecret123456"`,
			shouldDetect: true,
		},
		{
			name:         "Hardcoded API key",
			code:         `API_KEY = "sk-1234567890abcdef1234567890abcdef"`,
			shouldDetect: true,
		},
		{
			name:         "AWS access key",
			code:         `accessKey := "AKIAIOSFODNN7EXAMPLE"`,
			shouldDetect: true,
		},
		{
			name:         "Password from environment",
			code:         `password := os.Getenv("DB_PASSWORD")`,
			shouldDetect: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findings := matcher.ScanFileForPatterns("test.go", tc.code)

			if tc.shouldDetect {
				assert.NotEmpty(t, findings, "Expected to detect hardcoded secret")
			} else {
				assert.Empty(t, findings, "Should not flag environment variable usage")
			}
		})
	}
}

func TestSecurityPatternMatcher_CommandInjection(t *testing.T) {
	matcher := NewSecurityPatternMatcher()

	vulnerableCode := `exec.Command("sh", "-c", "ls " + userInput)`
	findings := matcher.ScanFileForPatterns("test.go", vulnerableCode)

	require.NotEmpty(t, findings, "Should detect command injection")
	assert.Equal(t, "Command Injection", findings[0].Pattern)
	assert.Equal(t, "CRITICAL", findings[0].Severity)
	assert.Contains(t, findings[0].Remediation, "allowlist")
}

func TestSecurityPatternMatcher_XSS(t *testing.T) {
	matcher := NewSecurityPatternMatcher()

	vulnerableCode := `element.innerHTML = userInput + "<div>"`
	findings := matcher.ScanFileForPatterns("test.js", vulnerableCode)

	require.NotEmpty(t, findings, "Should detect XSS vulnerability")
	assert.Equal(t, "Cross-Site Scripting (XSS)", findings[0].Pattern)
	assert.Equal(t, "HIGH", findings[0].Severity)
}

func TestSecurityPatternMatcher_WeakCryptography(t *testing.T) {
	matcher := NewSecurityPatternMatcher()

	testCases := []struct {
		name     string
		code     string
		expected bool
	}{
		{
			name:     "MD5 usage",
			code:     `hash := md5.Sum(data)`,
			expected: true,
		},
		{
			name:     "SHA1 usage",
			code:     `hash := sha1.New()`,
			expected: true,
		},
		{
			name:     "DES cipher",
			code:     `cipher := des.NewCipher(key)`,
			expected: true,
		},
		{
			name:     "Safe SHA256",
			code:     `hash := sha256.Sum256(data)`,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findings := matcher.ScanFileForPatterns("test.go", tc.code)

			if tc.expected {
				assert.NotEmpty(t, findings, "Should detect weak cryptography")
				if len(findings) > 0 {
					assert.Equal(t, "Weak Cryptographic Algorithm", findings[0].Pattern)
				}
			} else {
				assert.Empty(t, findings, "Should not flag secure algorithms")
			}
		})
	}
}

func TestSecurityPatternMatcher_PathTraversal(t *testing.T) {
	matcher := NewSecurityPatternMatcher()

	vulnerableCode := `filepath.Join(baseDir, userInput)`
	findings := matcher.ScanFileForPatterns("test.go", vulnerableCode)

	require.NotEmpty(t, findings, "Should detect path traversal risk")
	assert.Equal(t, "Path Traversal", findings[0].Pattern)
	assert.Contains(t, findings[0].Remediation, "allowlist")
}

func TestSecurityPatternMatcher_InsecureRandom(t *testing.T) {
	matcher := NewSecurityPatternMatcher()

	vulnerableCode := `token := rand.Intn(1000000)`
	findings := matcher.ScanFileForPatterns("test.go", vulnerableCode)

	require.NotEmpty(t, findings, "Should detect insecure random usage")
	assert.Equal(t, "Insecure Random Number Generation", findings[0].Pattern)
	assert.Equal(t, "MEDIUM", findings[0].Severity)
	assert.Contains(t, findings[0].Remediation, "crypto/rand")
}

func TestSecurityPatternMatcher_ConfidenceCalculation(t *testing.T) {
	matcher := NewSecurityPatternMatcher()

	testCases := []struct {
		name               string
		line               string
		expectedConfidence float64
		tolerance          float64
	}{
		{
			name:               "Production code",
			line:               `password := "secret123"`,
			expectedConfidence: 0.85,
			tolerance:          0.1,
		},
		{
			name:               "Test code",
			line:               `// test password := "secret123"`,
			expectedConfidence: 0.45,
			tolerance:          0.15,
		},
		{
			name:               "Example code",
			line:               `// Example: password := "example123"`,
			expectedConfidence: 0.55,
			tolerance:          0.15,
		},
	}

	pattern := SecurityPattern{
		Name:     "Hardcoded Secret",
		Severity: "CRITICAL",
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			confidence := matcher.calculateConfidence(tc.line, pattern)
			assert.InDelta(t, tc.expectedConfidence, confidence, tc.tolerance,
				"Confidence score should be within tolerance")
		})
	}
}

func TestFormatPatternFindings(t *testing.T) {
	findings := []VulnerabilityFinding{
		{
			Pattern:     "SQL Injection",
			FilePath:    "handlers/db.go",
			LineNumber:  42,
			Severity:    "CRITICAL",
			Category:    "Injection",
			Description: "Potential SQL injection",
			CodeSnippet: `db.Exec("SELECT * FROM users WHERE id = " + userId)`,
			Remediation: "Use parameterized queries",
			Confidence:  0.9,
		},
		{
			Pattern:     "Weak Cryptographic Algorithm",
			FilePath:    "utils/crypto.go",
			LineNumber:  15,
			Severity:    "HIGH",
			Category:    "Cryptography",
			Description: "Use of weak algorithm",
			CodeSnippet: `hash := md5.Sum(data)`,
			Remediation: "Use SHA-256 or better",
			Confidence:  0.85,
		},
	}

	report := formatPatternFindings(findings)

	assert.Contains(t, report, "CRITICAL SEVERITY")
	assert.Contains(t, report, "HIGH SEVERITY")
	assert.Contains(t, report, "SQL Injection")
	assert.Contains(t, report, "Weak Cryptographic Algorithm")
	assert.Contains(t, report, "handlers/db.go")
	assert.Contains(t, report, "90%") // Confidence
	assert.Contains(t, report, "Use parameterized queries")
}

func TestFilterBySeverity(t *testing.T) {
	findings := []VulnerabilityFinding{
		{Severity: "CRITICAL", Pattern: "Finding 1"},
		{Severity: "HIGH", Pattern: "Finding 2"},
		{Severity: "CRITICAL", Pattern: "Finding 3"},
		{Severity: "MEDIUM", Pattern: "Finding 4"},
	}

	critical := filterBySeverity(findings, "CRITICAL")
	assert.Len(t, critical, 2)
	assert.Equal(t, "Finding 1", critical[0].Pattern)
	assert.Equal(t, "Finding 3", critical[1].Pattern)

	high := filterBySeverity(findings, "HIGH")
	assert.Len(t, high, 1)
	assert.Equal(t, "Finding 2", high[0].Pattern)
}

func TestSecurityPatternMatcher_MultipleVulnerabilities(t *testing.T) {
	matcher := NewSecurityPatternMatcher()

	code := `
package main

import "database/sql"

func processUser(userInput string) {
	// SQL Injection vulnerability
	db.Exec("SELECT * FROM users WHERE id = " + userInput)

	// Hardcoded secret
	apiKey := "sk-1234567890abcdef1234567890abcdef"

	// Weak crypto
	hash := md5.Sum([]byte(userInput))
}
`

	findings := matcher.ScanFileForPatterns("main.go", code)

	assert.GreaterOrEqual(t, len(findings), 3, "Should detect multiple vulnerabilities")

	patterns := make(map[string]bool)
	for _, finding := range findings {
		patterns[finding.Pattern] = true
	}

	assert.True(t, patterns["SQL Injection"], "Should detect SQL injection")
	assert.True(t, patterns["Hardcoded Secret"], "Should detect hardcoded secret")
	assert.True(t, patterns["Weak Cryptographic Algorithm"], "Should detect weak crypto")
}

func TestSecurityPatternMatcher_NoFalsePositives(t *testing.T) {
	matcher := NewSecurityPatternMatcher()

	safeCode := `
package main

import (
	"crypto/sha256"
	"database/sql"
	"os"
)

func processUser(userInput string) error {
	// Safe parameterized query
	_, err := db.Query("SELECT * FROM users WHERE id = ?", userInput)
	if err != nil {
		return err
	}

	// Safe environment variable
	apiKey := os.Getenv("API_KEY")

	// Safe strong crypto
	hash := sha256.Sum256([]byte(userInput))

	return nil
}
`

	findings := matcher.ScanFileForPatterns("main.go", safeCode)

	// Should have minimal or no findings in properly secured code
	for _, finding := range findings {
		t.Logf("Potential false positive: %s at line %d (confidence: %.2f)",
			finding.Pattern, finding.LineNumber, finding.Confidence)
	}

	// Count high-confidence findings (potential false positives)
	highConfidenceFindings := 0
	for _, finding := range findings {
		if finding.Confidence > 0.7 {
			highConfidenceFindings++
		}
	}

	assert.Equal(t, 0, highConfidenceFindings,
		"Should not have high-confidence findings in safe code")
}

func TestFormatFinding(t *testing.T) {
	finding := VulnerabilityFinding{
		Pattern:     "SQL Injection",
		FilePath:    "test.go",
		LineNumber:  10,
		Severity:    "CRITICAL",
		Category:    "Injection",
		Description: "Test description",
		CodeSnippet: "test code",
		Remediation: "Test remediation",
		Confidence:  0.95,
	}

	formatted := formatFinding(finding)

	assert.Contains(t, formatted, "SQL Injection")
	assert.Contains(t, formatted, "CRITICAL")
	assert.Contains(t, formatted, "test.go")
	assert.Contains(t, formatted, "Line 10")
	assert.Contains(t, formatted, "95%")
	assert.Contains(t, formatted, "Test description")
	assert.Contains(t, formatted, "Test remediation")
}

func TestGetDefaultSecurityPatterns(t *testing.T) {
	patterns := getDefaultSecurityPatterns()

	assert.NotEmpty(t, patterns, "Should have default patterns")
	assert.GreaterOrEqual(t, len(patterns), 10, "Should have comprehensive pattern set")

	// Verify critical patterns are present
	patternNames := make(map[string]bool)
	for _, p := range patterns {
		patternNames[p.Name] = true
		assert.NotEmpty(t, p.Category, "Pattern should have category")
		assert.NotEmpty(t, p.Severity, "Pattern should have severity")
		assert.NotEmpty(t, p.Patterns, "Pattern should have regex patterns")
		assert.NotEmpty(t, p.Remediation, "Pattern should have remediation")
	}

	criticalPatterns := []string{
		"SQL Injection",
		"Hardcoded Secret",
		"Command Injection",
		"Cross-Site Scripting (XSS)",
		"Weak Cryptographic Algorithm",
	}

	for _, critical := range criticalPatterns {
		assert.True(t, patternNames[critical],
			"Should include critical pattern: "+critical)
	}
}

func BenchmarkSecurityPatternMatcher_ScanFile(b *testing.B) {
	matcher := NewSecurityPatternMatcher()

	code := strings.Repeat(`
func processData(input string) {
	db.Query("SELECT * FROM users WHERE id = ?", input)
	hash := sha256.Sum256([]byte(input))
}
`, 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = matcher.ScanFileForPatterns("test.go", code)
	}
}
