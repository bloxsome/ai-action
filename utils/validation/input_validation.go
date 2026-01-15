package validation

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidateGitHubOwner validates the GitHub owner parameter
func ValidateGitHubOwner(owner string) error {
	if owner == "" {
		return fmt.Errorf("owner cannot be empty")
	}

	// GitHub owner can contain alphanumeric characters and hyphens
	// Must not start or end with a hyphen
	// Maximum length is 39 characters
	if len(owner) > 39 {
		return fmt.Errorf("owner exceeds maximum length of 39 characters")
	}

	validOwnerRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`)
	if !validOwnerRegex.MatchString(owner) {
		return fmt.Errorf("owner contains invalid characters (only alphanumeric and hyphens allowed, cannot start/end with hyphen)")
	}

	// Check for path traversal attempts
	if strings.Contains(owner, "..") || strings.Contains(owner, "/") || strings.Contains(owner, "\\") {
		return fmt.Errorf("owner contains invalid path characters")
	}

	return nil
}

// ValidateGitHubRepo validates the GitHub repository parameter
func ValidateGitHubRepo(repo string) error {
	if repo == "" {
		return fmt.Errorf("repo cannot be empty")
	}

	// GitHub repo name rules:
	// - Can contain alphanumeric, hyphens, underscores, periods
	// - Maximum length is 100 characters
	if len(repo) > 100 {
		return fmt.Errorf("repo exceeds maximum length of 100 characters")
	}

	validRepoRegex := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	if !validRepoRegex.MatchString(repo) {
		return fmt.Errorf("repo contains invalid characters (only alphanumeric, hyphens, underscores, and periods allowed)")
	}

	// Check for path traversal attempts
	if strings.Contains(repo, "..") || strings.Contains(repo, "/") || strings.Contains(repo, "\\") {
		return fmt.Errorf("repo contains invalid path characters")
	}

	return nil
}

// ValidateGitRef validates the git reference (branch, tag, or commit SHA)
func ValidateGitRef(ref string) error {
	if ref == "" {
		// Empty ref is allowed (defaults to default branch)
		return nil
	}

	// Maximum length for git references
	if len(ref) > 255 {
		return fmt.Errorf("ref exceeds maximum length of 255 characters")
	}

	// Check for dangerous characters
	dangerousChars := []string{"..", "~", "^", ":", "?", "*", "[", "\\", " "}
	for _, char := range dangerousChars {
		if strings.Contains(ref, char) {
			return fmt.Errorf("ref contains invalid character: %s", char)
		}
	}

	// Disallow refs starting with special characters
	if strings.HasPrefix(ref, "-") || strings.HasPrefix(ref, "/") {
		return fmt.Errorf("ref cannot start with - or /")
	}

	return nil
}

// ValidatePRNumber validates the pull request number
func ValidatePRNumber(prNumber int) error {
	if prNumber < 0 {
		return fmt.Errorf("pr-number must be a positive integer or 0 (got %d)", prNumber)
	}

	// GitHub PR numbers have a reasonable upper limit
	if prNumber > 100000 {
		return fmt.Errorf("pr-number exceeds reasonable limit (got %d)", prNumber)
	}

	return nil
}

// ValidateMaxFiles validates the maximum files parameter
func ValidateMaxFiles(maxFiles int) error {
	if maxFiles <= 0 {
		return fmt.Errorf("max-files must be greater than 0 (got %d)", maxFiles)
	}

	// Set a reasonable upper limit to prevent resource exhaustion
	if maxFiles > 1000 {
		return fmt.Errorf("max-files exceeds reasonable limit of 1000 (got %d)", maxFiles)
	}

	return nil
}

// ValidateSeverityThreshold validates the severity threshold parameter
func ValidateSeverityThreshold(threshold int) error {
	if threshold < 1 || threshold > 10 {
		return fmt.Errorf("severity-threshold must be between 1 and 10 (got %d)", threshold)
	}

	return nil
}

// ValidateFilePaths validates the file paths pattern
func ValidateFilePaths(paths string) error {
	if paths == "" {
		// Empty paths is allowed (defaults to all files)
		return nil
	}

	// Check for dangerous path traversal patterns
	dangerousPatterns := []string{"../", "..\\", "/..", "\\..", "~"}
	for _, pattern := range dangerousPatterns {
		if strings.Contains(paths, pattern) {
			return fmt.Errorf("paths contains potentially dangerous pattern: %s", pattern)
		}
	}

	// Check for absolute paths (which could be used to escape repository)
	if strings.HasPrefix(paths, "/") || strings.HasPrefix(paths, "\\") {
		return fmt.Errorf("paths cannot contain absolute paths")
	}

	// Check for drive letters (Windows)
	if len(paths) >= 2 && paths[1] == ':' {
		return fmt.Errorf("paths cannot contain drive letters")
	}

	return nil
}

// ValidateAnalysisTypes validates the analysis types parameter
func ValidateAnalysisTypes(analysisTypes string) error {
	if analysisTypes == "" || analysisTypes == "all" {
		return nil
	}

	validTypes := map[string]bool{
		"general":      true,
		"secrets":      true,
		"auth":         true,
		"injection":    true,
		"crypto":       true,
		"dataflow":     true,
		"dependencies": true,
		"logic":        true,
		"web":          true,
		"all":          true,
	}

	types := strings.Split(analysisTypes, ",")
	for _, t := range types {
		t = strings.TrimSpace(strings.ToLower(t))
		if !validTypes[t] {
			return fmt.Errorf("invalid analysis type: %s (valid types: general, secrets, auth, injection, crypto, dataflow, dependencies, logic, web, all)", t)
		}
	}

	return nil
}

// ValidateQualityAnalysisType validates the quality analysis type parameter
func ValidateQualityAnalysisType(analysisType string) error {
	validTypes := map[string]bool{
		"quality":   true,
		"structure": true,
		"custom":    true,
	}

	if !validTypes[analysisType] {
		return fmt.Errorf("invalid analysis type: %s (valid types: quality, structure, custom)", analysisType)
	}

	return nil
}

// SanitizeInput performs basic input sanitization
func SanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Trim whitespace
	input = strings.TrimSpace(input)

	return input
}
