package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	cortexclient "ai-action/utils/cortex-client"

	"github.com/spf13/cobra"
)

var (
	toolkitsIncludeShared bool
	toolkitsLimit         int
	toolkitsOffset        int
)

// toolkitsCmd represents the toolkits command
var toolkitsCmd = &cobra.Command{
	Use:   "toolkits",
	Short: "Manage Cortex toolkits",
	Long: `Manage Cortex toolkits including listing and viewing details.

Toolkits are collections of tools that extend agent capabilities:
  • Pre-built tool collections
  • Custom tool integrations
  • API connectors
  • Data processing utilities

Examples:
  # List all toolkits (owned + shared)
  ai-action cortex toolkits list

  # List only your owned toolkits
  ai-action cortex toolkits list --include-shared=false

  # Get toolkit details
  ai-action cortex toolkits get security-toolkit`,
}

// toolkitsListCmd lists all toolkits
var toolkitsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all Cortex toolkits",
	Long: `List all toolkits accessible to you.

By default, this includes both owned and shared toolkits.
Use --include-shared=false to see only your owned toolkits.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := cortexclient.NewCortexClient(cortexURL, cortexToken)
		ctx := context.Background()

		toolkits, total, err := client.GetToolkits(ctx, toolkitsIncludeShared, toolkitsLimit, toolkitsOffset)
		if err != nil {
			return fmt.Errorf("failed to list toolkits: %w", err)
		}

		if len(toolkits) == 0 {
			fmt.Println("No toolkits found")
			return nil
		}

		// Create table writer
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintf(w, "NAME\tDESCRIPTION\tTOOLS\tOWNER\n")
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			strings.Repeat("-", 25),
			strings.Repeat("-", 40),
			strings.Repeat("-", 10),
			strings.Repeat("-", 20),
		)

		for _, toolkit := range toolkits {
			desc := toolkit.Description
			if len(desc) > 40 {
				desc = desc[:37] + "..."
			}

			toolCount := len(toolkit.Tools)
			toolCountStr := fmt.Sprintf("%d", toolCount)

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				toolkit.Name,
				desc,
				toolCountStr,
				toolkit.Owner,
			)
		}
		w.Flush()

		fmt.Printf("\nTotal: %d toolkits\n", total)
		return nil
	},
}

// toolkitsGetCmd gets details for a specific toolkit
var toolkitsGetCmd = &cobra.Command{
	Use:   "get [toolkit-name]",
	Short: "Get details for a specific toolkit",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := cortexclient.NewCortexClient(cortexURL, cortexToken)
		ctx := context.Background()

		toolkit, err := client.GetToolkitDetails(ctx, args[0])
		if err != nil {
			return fmt.Errorf("failed to get toolkit details: %w", err)
		}

		// Pretty print toolkit details
		jsonData, err := json.MarshalIndent(toolkit, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to format toolkit details: %w", err)
		}

		fmt.Println(string(jsonData))
		return nil
	},
}

func init() {
	cortexCmd.AddCommand(toolkitsCmd)

	// Add subcommands
	toolkitsCmd.AddCommand(toolkitsListCmd)
	toolkitsCmd.AddCommand(toolkitsGetCmd)

	// List command flags
	toolkitsListCmd.Flags().BoolVar(&toolkitsIncludeShared, "include-shared", true, "Include shared toolkits")
	toolkitsListCmd.Flags().IntVar(&toolkitsLimit, "limit", 50, "Maximum number of toolkits to return")
	toolkitsListCmd.Flags().IntVar(&toolkitsOffset, "offset", 0, "Offset for pagination")
}
