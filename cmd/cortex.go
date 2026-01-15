package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cortexURL   string
	cortexToken string
)

// cortexCmd represents the cortex command
var cortexCmd = &cobra.Command{
	Use:   "cortex",
	Short: "Interact with Cortex AI platform",
	Long: `Manage Cortex agents, toolkits, and data sources.

The Cortex platform provides centralized AI agent management with:
  • Agent creation and configuration
  • Toolkit and tool management
  • Data source integration
  • LLM model selection
  • Prompt management

Configuration:
  Set these environment variables or use flags:
    CORTEX_API_URL       - Cortex API base URL (default: https://api.dev.cortex.lilly.com)
    CORTEX_AUTH_TOKEN    - Your Cortex authentication token

Examples:
  # List all agents
  ai-action cortex agents list

  # Get agent details
  ai-action cortex agents get my-agent

  # Search for agents
  ai-action cortex agents search "security"

  # List toolkits
  ai-action cortex toolkits list

  # List data sources
  ai-action cortex datasources list`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Get Cortex URL from flag or environment
		if cortexURL == "" {
			cortexURL = os.Getenv("CORTEX_API_URL")
			if cortexURL == "" {
				cortexURL = "https://api.dev.cortex.lilly.com"
			}
		}

		// Get Cortex token from flag or environment
		if cortexToken == "" {
			cortexToken = os.Getenv("CORTEX_AUTH_TOKEN")
			if cortexToken == "" {
				fmt.Fprintf(os.Stderr, "Error: CORTEX_AUTH_TOKEN is required\n")
				fmt.Fprintf(os.Stderr, "Set it via environment variable or --cortex-token flag\n")
				os.Exit(1)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(cortexCmd)

	// Persistent flags for all cortex subcommands
	cortexCmd.PersistentFlags().StringVar(&cortexURL, "cortex-url", "", "Cortex API base URL")
	cortexCmd.PersistentFlags().StringVar(&cortexToken, "cortex-token", "", "Cortex authentication token")
}
