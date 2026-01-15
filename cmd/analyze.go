/*
Copyright © 2025 AI Action
*/
package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	aiHandler "ai-action/handlers/ai"
	fileReader "ai-action/handlers/filereader"
	prWriter "ai-action/handlers/prwriter"
	githubclient "ai-action/utils/github-client"
	"ai-action/utils/validation"
)

// analyzeCmd represents the analyze command
var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze code with custom AI prompts",
	Long: `Perform AI-powered code analysis using custom prompts.

This is the most flexible command - you provide the prompt, and the AI analyzes your code.

Examples:

  # Security analysis
  analyze --owner myorg --repo myrepo --prompt "Scan for security vulnerabilities and rate severity"

  # Performance analysis
  analyze --owner myorg --repo myrepo --prompt "Identify performance bottlenecks and suggest optimizations"

  # Documentation generation
  analyze --owner myorg --repo myrepo --prompt "Generate comprehensive API documentation"

  # Code review
  analyze --owner myorg --repo myrepo --prompt "Review code quality and suggest improvements"

  # Test generation
  analyze --owner myorg --repo myrepo --prompt "Generate unit tests for all functions"

  # Refactoring suggestions
  analyze --owner myorg --repo myrepo --prompt "Suggest refactoring opportunities for better maintainability"`,
	RunE: runAnalysis,
}

// runAnalysis executes the AI analysis with custom prompt
func runAnalysis(cmd *cobra.Command, args []string) error {
	// Get command flags
	owner, _ := cmd.Flags().GetString("owner")
	repo, _ := cmd.Flags().GetString("repo")
	ref, _ := cmd.Flags().GetString("ref")
	paths, _ := cmd.Flags().GetString("paths")
	maxFiles, _ := cmd.Flags().GetInt("max-files")
	prompt, _ := cmd.Flags().GetString("prompt")
	prNumber, _ := cmd.Flags().GetInt("pr-number")
	outputFormat, _ := cmd.Flags().GetString("output")

	// Sanitize inputs
	owner = validation.SanitizeInput(owner)
	repo = validation.SanitizeInput(repo)
	ref = validation.SanitizeInput(ref)
	paths = validation.SanitizeInput(paths)
	prompt = validation.SanitizeInput(prompt)

	// Validate all inputs
	if err := validation.ValidateGitHubOwner(owner); err != nil {
		return fmt.Errorf("invalid owner: %w", err)
	}
	if err := validation.ValidateGitHubRepo(repo); err != nil {
		return fmt.Errorf("invalid repo: %w", err)
	}
	if err := validation.ValidateGitRef(ref); err != nil {
		return fmt.Errorf("invalid ref: %w", err)
	}
	if err := validation.ValidateFilePaths(paths); err != nil {
		return fmt.Errorf("invalid paths: %w", err)
	}
	if err := validation.ValidateMaxFiles(maxFiles); err != nil {
		return fmt.Errorf("invalid max-files: %w", err)
	}
	if err := validation.ValidatePRNumber(prNumber); err != nil {
		return fmt.Errorf("invalid pr-number: %w", err)
	}

	// Validate prompt
	if prompt == "" {
		return fmt.Errorf("--prompt flag is required")
	}

	fmt.Printf("🤖 Starting AI analysis for %s/%s\n", owner, repo)
	if ref != "" {
		fmt.Printf("📍 Reference: %s\n", ref)
	}
	fmt.Printf("💬 Prompt: %s\n", prompt)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Initialize GitHub client
	privateKey := []byte(os.Getenv("GH_APP_PRIVATE_KEY"))
	appID, err := strconv.ParseInt(os.Getenv("GH_APP_ID"), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid GH_APP_ID: %w", err)
	}
	installationID, err := strconv.ParseInt(os.Getenv("GH_APP_INSTALLATION_ID"), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid GH_APP_INSTALLATION_ID: %w", err)
	}

	githubClient, err := githubclient.GetGitHubClient(privateKey, appID, installationID)
	if err != nil {
		return fmt.Errorf("failed to initialize GitHub client: %w", err)
	}

	// Initialize file reader
	reader := fileReader.NewFileReader(githubClient)

	// Get files from repository
	fmt.Println("📁 Fetching repository files...")
	files, err := reader.GetRepositoryFiles(ctx, owner, repo, ref, paths, maxFiles)
	if err != nil {
		return fmt.Errorf("failed to get repository files: %w", err)
	}

	if len(files) == 0 {
		fmt.Println("⚠️  No files found to analyze")
		return nil
	}

	fmt.Printf("📊 Found %d files to analyze\n", len(files))

	// Initialize AI handler
	fmt.Println("🤖 Initializing AI handler...")
	ai, err := aiHandler.NewAIHandler()
	if err != nil {
		return fmt.Errorf("failed to initialize AI handler: %w", err)
	}

	// Perform AI analysis with custom prompt
	fmt.Println("🔬 Performing AI analysis...")
	result, err := ai.AnalyzeMultipleFiles(ctx, files, prompt)
	if err != nil {
		return fmt.Errorf("AI analysis failed: %w", err)
	}

	// Output results
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Printf("🤖 AI Analysis Results for %s/%s\n", owner, repo)
	fmt.Println(strings.Repeat("=", 80))

	if outputFormat == "json" {
		// TODO: Implement JSON output
		fmt.Println(result)
	} else {
		fmt.Println(result)
	}
	fmt.Println(strings.Repeat("=", 80))

	// If PR number is provided, post results as comment
	if prNumber > 0 {
		fmt.Printf("\n💬 Writing analysis results to PR #%d\n", prNumber)

		prw := prWriter.NewPRWriter(githubClient)
		prComment := fmt.Sprintf("## 🤖 AI Analysis Results\n\n**Prompt**: %s\n\n%s", prompt, result)

		err = prw.WriteComment(ctx, owner, repo, prNumber, prComment)
		if err != nil {
			log.Error().Err(err).Int("pr_number", prNumber).Msg("Failed to write comment to PR")
			fmt.Printf("❌ Failed to write comment to PR #%d: %v\n", prNumber, err)
		} else {
			fmt.Printf("✅ Successfully posted analysis results to PR #%d\n", prNumber)
		}
	}

	return nil
}

func init() {
	rootCmd.AddCommand(analyzeCmd)

	// Required flags
	analyzeCmd.Flags().StringP("owner", "o", "", "GitHub repository owner (required)")
	analyzeCmd.Flags().StringP("repo", "r", "", "GitHub repository name (required)")
	analyzeCmd.Flags().StringP("prompt", "p", "", "AI analysis prompt (required)")

	// Optional flags
	analyzeCmd.Flags().String("ref", "", "Git reference (branch, tag, or commit SHA)")
	analyzeCmd.Flags().String("paths", "", "Comma-separated list of file patterns to analyze (e.g., '*.go,*.js')")
	analyzeCmd.Flags().IntP("max-files", "m", 20, "Maximum number of files to analyze")
	analyzeCmd.Flags().Int("pr-number", 0, "Pull request number to write results as a comment")
	analyzeCmd.Flags().String("output", "text", "Output format: text or json")

	// Mark required flags
	analyzeCmd.MarkFlagRequired("owner")
	analyzeCmd.MarkFlagRequired("repo")
	analyzeCmd.MarkFlagRequired("prompt")
}
