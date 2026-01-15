package ai

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// SecurityPattern represents a known security vulnerability pattern
type SecurityPattern struct {
	Name        string
	Category    string
	Severity    string
	Description string
	Patterns    []string // Regex patterns to match
	Examples    []string
	Remediation string
}

// VulnerabilityFinding represents a detected security issue
type VulnerabilityFinding struct {
	Pattern     string
	FilePath    string
	LineNumber  int
	Severity    string
	Category    string
	Description string
	CodeSnippet string
	Remediation string
	Confidence  float64 // 0.0 to 1.0
}

// SecurityPatternMatcher provides intelligent pattern-based vulnerability detection
type SecurityPatternMatcher struct {
	patterns []SecurityPattern
}

// NewSecurityPatternMatcher creates a new pattern matcher with predefined security patterns
func NewSecurityPatternMatcher() *SecurityPatternMatcher {
	return &SecurityPatternMatcher{
		patterns: getDefaultSecurityPatterns(),
	}
}

// getDefaultSecurityPatterns returns a comprehensive set of security patterns
func getDefaultSecurityPatterns() []SecurityPattern {
	return []SecurityPattern{
		// SQL Injection Patterns
		{
			Name:        "SQL Injection",
			Category:    "Injection",
			Severity:    "CRITICAL",
			Description: "Potential SQL injection vulnerability from unsanitized user input",
			Patterns: []string{
				`(?i).*\bexec\s*\(\s*[\"']?\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)`,
				`(?i).*\bquery\s*\(\s*[\"']?\s*(SELECT|INSERT|UPDATE|DELETE|DROP).*\+.*\)`,
				`(?i).*\bdb\.raw\s*\(.*\+.*\)`,
				`(?i).*fmt\.Sprintf\s*\(.*SELECT.*%`,
			},
			Examples: []string{
				`db.Exec("SELECT * FROM users WHERE id = " + userInput)`,
				`query := fmt.Sprintf("SELECT * FROM %s WHERE id = %s", table, id)`,
			},
			Remediation: "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.",
		},
		// Hardcoded Secrets
		{
			Name:        "Hardcoded Secret",
			Category:    "Secrets",
			Severity:    "CRITICAL",
			Description: "Hardcoded credentials, API keys, or secrets detected in source code",
			Patterns: []string{
				`(?i)(password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{8,}[\"']`,
				`(?i)(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*[\"'][^\"']{16,}[\"']`,
				`(?i)(secret|token|auth[_-]?token)\s*[:=]\s*[\"'][^\"']{16,}[\"']`,
				`(?i)(private[_-]?key|priv[_-]?key)\s*[:=]\s*[\"'][^\"']{32,}[\"']`,
				`(?i)sk-[a-zA-Z0-9]{32,}`, // OpenAI style keys
				`(?i)AKIA[0-9A-Z]{16}`,    // AWS access keys
			},
			Examples: []string{
				`password := "SuperSecret123"`,
				`API_KEY = "sk-1234567890abcdef1234567890abcdef"`,
			},
			Remediation: "Store secrets in environment variables, secret management systems (e.g., AWS Secrets Manager, HashiCorp Vault), or encrypted configuration files.",
		},
		// Command Injection
		{
			Name:        "Command Injection",
			Category:    "Injection",
			Severity:    "CRITICAL",
			Description: "Potential command injection vulnerability from unsanitized input",
			Patterns: []string{
				`(?i).*exec\.Command\s*\([^,]+,\s*.*\+.*\)`,
				`(?i).*os\.system\s*\(.*\+.*\)`,
				`(?i).*subprocess\.call\s*\(.*\+.*\)`,
				`(?i).*Runtime\.getRuntime\(\)\.exec\s*\(.*\+.*\)`,
			},
			Examples: []string{
				`exec.Command("sh", "-c", "ls " + userInput)`,
				`os.system("cat " + filename)`,
			},
			Remediation: "Avoid using shell commands with user input. If necessary, use allowlists and properly escape/validate all inputs.",
		},
		// XSS Vulnerabilities
		{
			Name:        "Cross-Site Scripting (XSS)",
			Category:    "Web Security",
			Severity:    "HIGH",
			Description: "Potential XSS vulnerability from unsanitized output",
			Patterns: []string{
				`(?i).*innerHTML\s*=\s*.*\+`,
				`(?i).*document\.write\s*\(.*\+.*\)`,
				`(?i).*html\.UnescapeString\s*\(`,
				`(?i).*dangerouslySetInnerHTML`,
			},
			Examples: []string{
				`element.innerHTML = userInput`,
				`document.write("<div>" + userData + "</div>")`,
			},
			Remediation: "Always sanitize and escape user input before rendering in HTML. Use secure templating engines with auto-escaping.",
		},
		// Weak Cryptography
		{
			Name:        "Weak Cryptographic Algorithm",
			Category:    "Cryptography",
			Severity:    "HIGH",
			Description: "Use of weak or deprecated cryptographic algorithms",
			Patterns: []string{
				`(?i).*\b(MD5|SHA1|DES|RC4)\b`,
				`(?i).*crypto\/(md5|sha1|des|rc4)`,
				`(?i).*MessageDigest\.getInstance\s*\(\s*[\"'](MD5|SHA-1|SHA1)[\"']\s*\)`,
			},
			Examples: []string{
				`hash := md5.Sum(data)`,
				`cipher := des.NewCipher(key)`,
			},
			Remediation: "Use modern, secure algorithms: SHA-256 or SHA-3 for hashing, AES-256 for encryption, and RSA-2048+ or ECC for asymmetric encryption.",
		},
		// Path Traversal
		{
			Name:        "Path Traversal",
			Category:    "File Security",
			Severity:    "HIGH",
			Description: "Potential path traversal vulnerability allowing access to unauthorized files",
			Patterns: []string{
				`(?i).*filepath\.Join\s*\([^)]*\+[^)]*\)`,
				`(?i).*os\.Open\s*\([^)]*\+[^)]*\)`,
				`(?i).*ioutil\.ReadFile\s*\([^)]*\+[^)]*\)`,
				`(?i).*\.\./`,
			},
			Examples: []string{
				`filepath.Join(baseDir, userInput)`,
				`os.Open("/var/data/" + filename)`,
			},
			Remediation: "Validate and sanitize file paths. Use allowlists for permitted paths and reject paths containing '..' or absolute path indicators.",
		},
		// Insecure Random
		{
			Name:        "Insecure Random Number Generation",
			Category:    "Cryptography",
			Severity:    "MEDIUM",
			Description: "Use of predictable random number generator for security-sensitive operations",
			Patterns: []string{
				`(?i).*math/rand\.(Int|Float|Intn)`,
				`(?i).*Random\(\)\.Next`,
				`(?i).*Math\.random\(\)`,
			},
			Examples: []string{
				`token := rand.Intn(1000000)`,
				`sessionId := Math.random()`,
			},
			Remediation: "Use cryptographically secure random number generators: crypto/rand in Go, secrets module in Python, crypto.getRandomValues in JavaScript.",
		},
		// Missing Authentication
		{
			Name:        "Missing Authentication Check",
			Category:    "Authentication",
			Severity:    "CRITICAL",
			Description: "Endpoint or function missing authentication verification",
			Patterns: []string{
				`(?i).*router\.(GET|POST|PUT|DELETE|PATCH)\s*\([^,]+,\s*(?!.*auth).*\)`,
				`(?i).*@(Get|Post|Put|Delete|Patch)Mapping\s*(?!.*\bauth)`,
			},
			Examples: []string{
				`router.GET("/admin/users", getUsersHandler)`,
				`@GetMapping("/api/sensitive-data")`,
			},
			Remediation: "Implement authentication middleware for all protected endpoints. Verify user identity and permissions before processing requests.",
		},
		// Insecure Deserialization
		{
			Name:        "Insecure Deserialization",
			Category:    "Injection",
			Severity:    "CRITICAL",
			Description: "Unsafe deserialization of untrusted data",
			Patterns: []string{
				`(?i).*json\.Unmarshal\s*\([^,]+\s*,\s*&\s*interface`,
				`(?i).*pickle\.loads?\s*\(`,
				`(?i).*ObjectInputStream\s*\(`,
				`(?i).*unserialize\s*\(`,
			},
			Examples: []string{
				`pickle.loads(user_data)`,
				`ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())`,
			},
			Remediation: "Avoid deserializing untrusted data. If necessary, use safe formats like JSON with strict schemas, validate input, and use allowlists for permitted classes.",
		},
		// Missing Rate Limiting
		{
			Name:        "Missing Rate Limiting",
			Category:    "Business Logic",
			Severity:    "MEDIUM",
			Description: "API endpoint without rate limiting protection",
			Patterns: []string{
				`(?i).*router\.(POST|PUT|DELETE)\s*\([^,]+,\s*(?!.*rate).*\)`,
				`(?i).*@(Post|Put|Delete)Mapping\s*(?!.*rate)`,
			},
			Examples: []string{
				`router.POST("/api/login", loginHandler)`,
				`router.POST("/api/payment", processPayment)`,
			},
			Remediation: "Implement rate limiting for sensitive endpoints (login, payment, API calls) to prevent brute force and DoS attacks.",
		},
	}
}

// ScanFileForPatterns scans a file for known security patterns
func (spm *SecurityPatternMatcher) ScanFileForPatterns(filePath, content string) []VulnerabilityFinding {
	var findings []VulnerabilityFinding
	lines := strings.Split(content, "\n")

	for _, pattern := range spm.patterns {
		for _, regexPattern := range pattern.Patterns {
			re, err := regexp.Compile(regexPattern)
			if err != nil {
				continue
			}

			for lineNum, line := range lines {
				if matches := re.FindStringSubmatch(line); matches != nil {
					confidence := spm.calculateConfidence(line, pattern)

					findings = append(findings, VulnerabilityFinding{
						Pattern:     pattern.Name,
						FilePath:    filePath,
						LineNumber:  lineNum + 1,
						Severity:    pattern.Severity,
						Category:    pattern.Category,
						Description: pattern.Description,
						CodeSnippet: strings.TrimSpace(line),
						Remediation: pattern.Remediation,
						Confidence:  confidence,
					})
				}
			}
		}
	}

	return findings
}

// calculateConfidence determines the confidence level of a pattern match
func (spm *SecurityPatternMatcher) calculateConfidence(line string, pattern SecurityPattern) float64 {
	confidence := 0.7 // Base confidence

	// Increase confidence for critical patterns in sensitive contexts
	if pattern.Severity == "CRITICAL" {
		confidence += 0.15
	}

	// Check for obvious test or example code (decrease confidence)
	lowerLine := strings.ToLower(line)
	if strings.Contains(lowerLine, "test") ||
	   strings.Contains(lowerLine, "example") ||
	   strings.Contains(lowerLine, "mock") ||
	   strings.Contains(lowerLine, "demo") {
		confidence -= 0.3
	}

	// Check for comments (decrease confidence)
	if strings.Contains(strings.TrimSpace(line), "//") ||
	   strings.Contains(strings.TrimSpace(line), "#") ||
	   strings.Contains(strings.TrimSpace(line), "/*") {
		confidence -= 0.4
	}

	// Ensure confidence is within bounds
	if confidence < 0.1 {
		confidence = 0.1
	}
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// AnalyzeWithAIEnhancement combines pattern matching with AI analysis
func (ah *AIHandler) AnalyzeWithAIEnhancement(ctx context.Context, files []FileContext) (string, error) {
	// First, run pattern-based detection
	matcher := NewSecurityPatternMatcher()
	var allFindings []VulnerabilityFinding

	for _, file := range files {
		findings := matcher.ScanFileForPatterns(file.Path, file.Content)
		allFindings = append(allFindings, findings...)
	}

	// Format pattern findings
	patternReport := formatPatternFindings(allFindings)

	// Then enhance with AI analysis
	question := fmt.Sprintf(`You are an expert security analyst. I've run an automated pattern-based scan that found the following potential issues:

%s

Please:
1. Validate these findings and identify false positives
2. Provide additional context and severity assessment for each real vulnerability
3. Identify any security issues the pattern scanner may have missed
4. Prioritize findings by actual risk and exploitability
5. Provide specific, actionable remediation steps

Focus on practical security risks in a production environment.`, patternReport)

	aiAnalysis, err := ah.AnalyzeMultipleFiles(ctx, files, question)
	if err != nil {
		return patternReport, err
	}

	// Combine results
	return fmt.Sprintf("# AI-Enhanced Security Analysis\n\n## Pattern-Based Detection Results\n\n%s\n\n## AI Validation and Deep Analysis\n\n%s",
		patternReport, aiAnalysis), nil
}

// formatPatternFindings formats vulnerability findings into a readable report
func formatPatternFindings(findings []VulnerabilityFinding) string {
	if len(findings) == 0 {
		return "No security patterns detected by automated scanner."
	}

	var report strings.Builder
	report.WriteString(fmt.Sprintf("Found %d potential security issues:\n\n", len(findings)))

	// Group by severity
	criticalFindings := filterBySeverity(findings, "CRITICAL")
	highFindings := filterBySeverity(findings, "HIGH")
	mediumFindings := filterBySeverity(findings, "MEDIUM")
	lowFindings := filterBySeverity(findings, "LOW")

	if len(criticalFindings) > 0 {
		report.WriteString("### 🚨 CRITICAL SEVERITY\n\n")
		for _, f := range criticalFindings {
			report.WriteString(formatFinding(f))
		}
	}

	if len(highFindings) > 0 {
		report.WriteString("### 🔴 HIGH SEVERITY\n\n")
		for _, f := range highFindings {
			report.WriteString(formatFinding(f))
		}
	}

	if len(mediumFindings) > 0 {
		report.WriteString("### 🟠 MEDIUM SEVERITY\n\n")
		for _, f := range mediumFindings {
			report.WriteString(formatFinding(f))
		}
	}

	if len(lowFindings) > 0 {
		report.WriteString("### 🟡 LOW SEVERITY\n\n")
		for _, f := range lowFindings {
			report.WriteString(formatFinding(f))
		}
	}

	return report.String()
}

// filterBySeverity filters findings by severity level
func filterBySeverity(findings []VulnerabilityFinding, severity string) []VulnerabilityFinding {
	var filtered []VulnerabilityFinding
	for _, f := range findings {
		if f.Severity == severity {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// formatFinding formats a single vulnerability finding
func formatFinding(f VulnerabilityFinding) string {
	return fmt.Sprintf(`**%s** - %s
- **File**: %s (Line %d)
- **Category**: %s
- **Confidence**: %.0f%%
- **Code**:
  `+"`"+`%s`+"`"+`
- **Description**: %s
- **Remediation**: %s

`, f.Pattern, f.Severity, f.FilePath, f.LineNumber, f.Category,
   f.Confidence*100, f.CodeSnippet, f.Description, f.Remediation)
}
