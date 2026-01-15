/*
Copyright © 2025 AI Action
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ai-action",
	Short: "Generic AI-powered code analysis using AWS Bedrock",
	Long: `AI Action is a flexible GitHub Action that leverages AWS Bedrock (Claude AI)
to perform any AI-powered analysis on your codebase.

Use it for:
- Custom code analysis with your own prompts
- Security vulnerability scanning
- Code quality reviews
- Documentation generation
- Code explanation and refactoring suggestions
- Test generation
- Any other AI-powered code task

Examples:
  # Analyze code with custom prompt
  ai-action analyze --owner myorg --repo myrepo --prompt "Find performance bottlenecks"

  # Generate documentation
  ai-action analyze --owner myorg --repo myrepo --prompt "Generate API documentation"

  # Security scan
  ai-action analyze --owner myorg --repo myrepo --prompt "Scan for security vulnerabilities"`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Global flags that apply to all commands
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().Bool("json", false, "Output results in JSON format")
}
