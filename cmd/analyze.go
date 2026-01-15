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
	cortexclient "ai-action/utils/cortex-client"
	githubclient "ai-action/utils/github-client"
	"ai-action/utils/validation"
)

// analyzeCmd represents the analyze command
var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze code with custom AI prompts",
	Long: `Perform AI-powered code analysis using custom prompts.

This is the most flexible command - you provide the prompt, and the AI analyzes your code.

You can either use direct AI analysis (AWS Bedrock) or optionally route through a Cortex agent.

Examples:

  # Security analysis (direct AI)
  analyze --owner myorg --repo myrepo --prompt "Scan for security vulnerabilities and rate severity"

  # Performance analysis using Cortex agent
  analyze --owner myorg --repo myrepo --prompt "Identify performance bottlenecks" \
    --cortex-agent performance-analyzer

  # Documentation generation
  analyze --owner myorg --repo myrepo --prompt "Generate comprehensive API documentation"

  # Code review with custom Cortex URL and token
  analyze --owner myorg --repo myrepo --prompt "Review code quality" \
    --cortex-agent code-reviewer \
    --cortex-url https://api.cortex.lilly.com \
    --cortex-token $CORTEX_TOKEN`,
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

	// Cortex integration flags
	cortexAgent, _ := cmd.Flags().GetString("cortex-agent")
	cortexURL, _ := cmd.Flags().GetString("cortex-url")
	cortexToken, _ := cmd.Flags().GetString("cortex-token")
	useCortex := cortexAgent != ""

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
	if useCortex {
		fmt.Printf("🧠 Using Cortex Agent: %s\n", cortexAgent)
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

	var result string

	// Choose analysis method: Cortex or direct AI
	if useCortex {
		// Use Cortex agent for analysis
		result, err = performCortexAnalysis(ctx, cortexAgent, cortexURL, cortexToken, files, prompt)
		if err != nil {
			return fmt.Errorf("Cortex analysis failed: %w", err)
		}
	} else {
		// Use direct AI analysis via AWS Bedrock
		fmt.Println("🤖 Initializing AI handler...")
		ai, err := aiHandler.NewAIHandler()
		if err != nil {
			return fmt.Errorf("failed to initialize AI handler: %w", err)
		}

		fmt.Println("🔬 Performing AI analysis...")
		result, err = ai.AnalyzeMultipleFiles(ctx, files, prompt)
		if err != nil {
			return fmt.Errorf("AI analysis failed: %w", err)
		}
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

// performCortexAnalysis uses a Cortex agent to analyze files
func performCortexAnalysis(ctx context.Context, agentName, cortexURL, cortexToken string, files []aiHandler.FileContext, prompt string) (string, error) {
	// Set defaults for Cortex URL and token if not provided
	if cortexURL == "" {
		cortexURL = os.Getenv("CORTEX_API_URL")
		if cortexURL == "" {
			cortexURL = "https://api.dev.cortex.lilly.com"
		}
	}

	if cortexToken == "" {
		cortexToken = os.Getenv("CORTEX_AUTH_TOKEN")
		if cortexToken == "" {
			return "", fmt.Errorf("CORTEX_AUTH_TOKEN is required for Cortex integration")
		}
	}

	fmt.Printf("🧠 Connecting to Cortex at %s\n", cortexURL)

	// Initialize Cortex client
	client := cortexclient.NewCortexClient(cortexURL, cortexToken)

	// Verify agent exists
	fmt.Printf("🔍 Verifying Cortex agent '%s' exists...\n", agentName)
	exists, err := client.CheckAgentExists(ctx, agentName)
	if err != nil {
		return "", fmt.Errorf("failed to check if agent exists: %w", err)
	}
	if !exists {
		return "", fmt.Errorf("Cortex agent '%s' not found", agentName)
	}

	// Get agent details
	agent, err := client.GetAgentDetails(ctx, agentName)
	if err != nil {
		return "", fmt.Errorf("failed to get agent details: %w", err)
	}

	fmt.Printf("✓ Using agent: %s (model: %s)\n", agent.Name, agent.Model)
	if len(agent.Toolkits) > 0 {
		fmt.Printf("  Toolkits: %s\n", strings.Join(agent.Toolkits, ", "))
	}
	if len(agent.DataSources) > 0 {
		fmt.Printf("  Data sources: %s\n", strings.Join(agent.DataSources, ", "))
	}

	fmt.Println("🔬 Performing Cortex AI analysis...")

	// Note: In a full implementation, we would call the Cortex inference API here
	// For now, we'll return a placeholder indicating Cortex integration is working
	// The actual Cortex inference endpoint would be something like:
	// POST /agents/{agent_name}/infer or /chat with the prompt
	//
	// The prompt would be constructed with:
	// fileContents := formatFilesForPrompt(files)
	// fullPrompt := fmt.Sprintf("%s\n\nHere are the files to analyze:\n\n%s\n\nPlease provide a detailed analysis addressing the prompt above.", prompt, fileContents)

	result := fmt.Sprintf(`## Cortex Analysis Results

**Agent**: %s
**Model**: %s
**Toolkits**: %s
**Data Sources**: %s

---

*Note: Full Cortex inference integration requires the Cortex inference API endpoint.*
*This validates that the Cortex agent exists and is accessible.*
*To complete the integration, implement the Cortex inference API call here.*

Files analyzed: %d
Prompt: %s`,
		agent.Name,
		agent.Model,
		strings.Join(agent.Toolkits, ", "),
		strings.Join(agent.DataSources, ", "),
		len(files),
		prompt)

	return result, nil
}

// formatFilesForPrompt formats repository files into a readable string for the AI prompt
func formatFilesForPrompt(files []aiHandler.FileContext) string {
	var builder strings.Builder

	for i, file := range files {
		builder.WriteString(fmt.Sprintf("\n--- File %d: %s ---\n", i+1, file.Path))
		builder.WriteString(file.Content)
		builder.WriteString("\n")
	}

	return builder.String()
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

	// Cortex integration flags
	analyzeCmd.Flags().String("cortex-agent", "", "Cortex agent name to use for analysis (enables Cortex mode)")
	analyzeCmd.Flags().String("cortex-url", "", "Cortex API base URL (default: https://api.dev.cortex.lilly.com or CORTEX_API_URL env)")
	analyzeCmd.Flags().String("cortex-token", "", "Cortex authentication token (default: CORTEX_AUTH_TOKEN env)")

	// Mark required flags
	analyzeCmd.MarkFlagRequired("owner")
	analyzeCmd.MarkFlagRequired("repo")
	analyzeCmd.MarkFlagRequired("prompt")
}
