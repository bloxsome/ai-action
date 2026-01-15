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
	datasourcesIncludeShared bool
	datasourcesLimit         int
	datasourcesOffset        int
)

// datasourcesCmd represents the datasources command
var datasourcesCmd = &cobra.Command{
	Use:   "datasources",
	Short: "Manage Cortex data sources",
	Long: `Manage Cortex data sources including listing and viewing details.

Data sources provide context and knowledge to agents:
  • Document collections
  • Knowledge bases
  • Database connections
  • API data sources
  • File repositories

Examples:
  # List all data sources (owned + shared)
  ai-action cortex datasources list

  # List only your owned data sources
  ai-action cortex datasources list --include-shared=false

  # Get data source details
  ai-action cortex datasources get security-docs`,
}

// datasourcesListCmd lists all data sources
var datasourcesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all Cortex data sources",
	Long: `List all data sources accessible to you.

By default, this includes both owned and shared data sources.
Use --include-shared=false to see only your owned data sources.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := cortexclient.NewCortexClient(cortexURL, cortexToken)
		ctx := context.Background()

		dataSources, total, err := client.GetDataSources(ctx, datasourcesIncludeShared, datasourcesLimit, datasourcesOffset)
		if err != nil {
			return fmt.Errorf("failed to list data sources: %w", err)
		}

		if len(dataSources) == 0 {
			fmt.Println("No data sources found")
			return nil
		}

		// Create table writer
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintf(w, "NAME\tTYPE\tDESCRIPTION\tFILES\tOWNER\n")
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			strings.Repeat("-", 25),
			strings.Repeat("-", 15),
			strings.Repeat("-", 40),
			strings.Repeat("-", 8),
			strings.Repeat("-", 20),
		)

		for _, ds := range dataSources {
			desc := ds.Description
			if len(desc) > 40 {
				desc = desc[:37] + "..."
			}

			fileCountStr := fmt.Sprintf("%d", ds.FileCount)

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				ds.Name,
				ds.Type,
				desc,
				fileCountStr,
				ds.Owner,
			)
		}
		w.Flush()

		fmt.Printf("\nTotal: %d data sources\n", total)
		return nil
	},
}

// datasourcesGetCmd gets details for a specific data source
var datasourcesGetCmd = &cobra.Command{
	Use:   "get [datasource-name]",
	Short: "Get details for a specific data source",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := cortexclient.NewCortexClient(cortexURL, cortexToken)
		ctx := context.Background()

		dataSource, err := client.GetDataSourceDetails(ctx, args[0])
		if err != nil {
			return fmt.Errorf("failed to get data source details: %w", err)
		}

		// Pretty print data source details
		jsonData, err := json.MarshalIndent(dataSource, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to format data source details: %w", err)
		}

		fmt.Println(string(jsonData))
		return nil
	},
}

func init() {
	cortexCmd.AddCommand(datasourcesCmd)

	// Add subcommands
	datasourcesCmd.AddCommand(datasourcesListCmd)
	datasourcesCmd.AddCommand(datasourcesGetCmd)

	// List command flags
	datasourcesListCmd.Flags().BoolVar(&datasourcesIncludeShared, "include-shared", true, "Include shared data sources")
	datasourcesListCmd.Flags().IntVar(&datasourcesLimit, "limit", 50, "Maximum number of data sources to return")
	datasourcesListCmd.Flags().IntVar(&datasourcesOffset, "offset", 0, "Offset for pagination")
}
