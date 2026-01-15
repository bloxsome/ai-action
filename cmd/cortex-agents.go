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
	includeShared bool
	limit         int
	offset        int
	agentModel    string
	agentTemp     float64
	agentToolkits []string
	agentSources  []string
)

// agentsCmd represents the agents command
var agentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "Manage Cortex agents",
	Long: `Manage Cortex agents including listing, creating, updating, and deleting.

Agents are AI assistants configured with:
  • LLM model selection
  • Temperature and generation parameters
  • Associated toolkits for extended capabilities
  • Data sources for context and knowledge

Examples:
  # List all agents (owned + shared)
  ai-action cortex agents list

  # List only your owned agents
  ai-action cortex agents list --include-shared=false

  # Get agent details
  ai-action cortex agents get my-agent

  # Search for agents
  ai-action cortex agents search "security"

  # Create a new agent
  ai-action cortex agents create my-agent \
    --description "Security analysis agent" \
    --model "claude-3-5-sonnet-20241022" \
    --temperature 0.7 \
    --toolkits security-toolkit,code-analysis

  # Delete an agent
  ai-action cortex agents delete my-agent`,
}

// agentsListCmd lists all agents
var agentsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all Cortex agents",
	Long: `List all agents accessible to you.

By default, this includes both owned and shared agents.
Use --include-shared=false to see only your owned agents.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := cortexclient.NewCortexClient(cortexURL, cortexToken)
		ctx := context.Background()

		agents, total, err := client.GetAgents(ctx, includeShared, limit, offset)
		if err != nil {
			return fmt.Errorf("failed to list agents: %w", err)
		}

		if len(agents) == 0 {
			fmt.Println("No agents found")
			return nil
		}

		// Create table writer
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintf(w, "NAME\tMODEL\tTOOLKITS\tDATA SOURCES\tOWNER\n")
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			strings.Repeat("-", 20),
			strings.Repeat("-", 30),
			strings.Repeat("-", 20),
			strings.Repeat("-", 20),
			strings.Repeat("-", 20),
		)

		for _, agent := range agents {
			toolkitStr := strings.Join(agent.Toolkits, ", ")
			if len(toolkitStr) > 20 {
				toolkitStr = toolkitStr[:17] + "..."
			}
			sourceStr := strings.Join(agent.DataSources, ", ")
			if len(sourceStr) > 20 {
				sourceStr = sourceStr[:17] + "..."
			}

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				agent.Name,
				agent.Model,
				toolkitStr,
				sourceStr,
				agent.Owner,
			)
		}
		w.Flush()

		fmt.Printf("\nTotal: %d agents\n", total)
		return nil
	},
}

// agentsGetCmd gets details for a specific agent
var agentsGetCmd = &cobra.Command{
	Use:   "get [agent-name]",
	Short: "Get details for a specific agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := cortexclient.NewCortexClient(cortexURL, cortexToken)
		ctx := context.Background()

		agent, err := client.GetAgentDetails(ctx, args[0])
		if err != nil {
			return fmt.Errorf("failed to get agent details: %w", err)
		}

		// Pretty print agent details
		jsonData, err := json.MarshalIndent(agent, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to format agent details: %w", err)
		}

		fmt.Println(string(jsonData))
		return nil
	},
}

// agentsSearchCmd searches for agents
var agentsSearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search for agents by query",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := cortexclient.NewCortexClient(cortexURL, cortexToken)
		ctx := context.Background()

		agents, total, err := client.SearchAgents(ctx, args[0], limit, offset)
		if err != nil {
			return fmt.Errorf("failed to search agents: %w", err)
		}

		if len(agents) == 0 {
			fmt.Printf("No agents found matching '%s'\n", args[0])
			return nil
		}

		// Create table writer
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintf(w, "NAME\tDESCRIPTION\tMODEL\tOWNER\n")
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			strings.Repeat("-", 20),
			strings.Repeat("-", 40),
			strings.Repeat("-", 30),
			strings.Repeat("-", 20),
		)

		for _, agent := range agents {
			desc := agent.Description
			if len(desc) > 40 {
				desc = desc[:37] + "..."
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				agent.Name,
				desc,
				agent.Model,
				agent.Owner,
			)
		}
		w.Flush()

		fmt.Printf("\nFound %d agents\n", total)
		return nil
	},
}

// agentsCreateCmd creates a new agent
var agentsCreateCmd = &cobra.Command{
	Use:   "create [agent-name]",
	Short: "Create a new Cortex agent",
	Long: `Create a new agent with the specified configuration.

Example:
  ai-action cortex agents create my-agent \
    --description "Security analysis agent" \
    --model "claude-3-5-sonnet-20241022" \
    --temperature 0.7 \
    --toolkits security-toolkit,code-analysis \
    --datasources security-docs,cve-database`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := cortexclient.NewCortexClient(cortexURL, cortexToken)
		ctx := context.Background()

		agentName := args[0]
		description, _ := cmd.Flags().GetString("description")

		agent := &cortexclient.Agent{
			Name:        agentName,
			Description: description,
			Model:       agentModel,
			Temperature: agentTemp,
			Toolkits:    agentToolkits,
			DataSources: agentSources,
		}

		if err := client.CreateAgent(ctx, agent); err != nil {
			return fmt.Errorf("failed to create agent: %w", err)
		}

		fmt.Printf("✓ Successfully created agent '%s'\n", agentName)
		return nil
	},
}

// agentsDeleteCmd deletes an agent
var agentsDeleteCmd = &cobra.Command{
	Use:   "delete [agent-name]",
	Short: "Delete a Cortex agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := cortexclient.NewCortexClient(cortexURL, cortexToken)
		ctx := context.Background()

		agentName := args[0]

		// Confirm deletion
		fmt.Printf("Are you sure you want to delete agent '%s'? (y/N): ", agentName)
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
			fmt.Println("Deletion cancelled")
			return nil
		}

		if err := client.DeleteAgent(ctx, agentName); err != nil {
			return fmt.Errorf("failed to delete agent: %w", err)
		}

		fmt.Printf("✓ Successfully deleted agent '%s'\n", agentName)
		return nil
	},
}

func init() {
	cortexCmd.AddCommand(agentsCmd)

	// Add subcommands
	agentsCmd.AddCommand(agentsListCmd)
	agentsCmd.AddCommand(agentsGetCmd)
	agentsCmd.AddCommand(agentsSearchCmd)
	agentsCmd.AddCommand(agentsCreateCmd)
	agentsCmd.AddCommand(agentsDeleteCmd)

	// List command flags
	agentsListCmd.Flags().BoolVar(&includeShared, "include-shared", true, "Include shared agents")
	agentsListCmd.Flags().IntVar(&limit, "limit", 50, "Maximum number of agents to return")
	agentsListCmd.Flags().IntVar(&offset, "offset", 0, "Offset for pagination")

	// Search command flags
	agentsSearchCmd.Flags().IntVar(&limit, "limit", 50, "Maximum number of agents to return")
	agentsSearchCmd.Flags().IntVar(&offset, "offset", 0, "Offset for pagination")

	// Create command flags
	agentsCreateCmd.Flags().String("description", "", "Agent description")
	agentsCreateCmd.Flags().StringVar(&agentModel, "model", "claude-3-5-sonnet-20241022", "LLM model to use")
	agentsCreateCmd.Flags().Float64Var(&agentTemp, "temperature", 0.7, "Temperature for generation (0.0-1.0)")
	agentsCreateCmd.Flags().StringSliceVar(&agentToolkits, "toolkits", []string{}, "Comma-separated list of toolkit names")
	agentsCreateCmd.Flags().StringSliceVar(&agentSources, "datasources", []string{}, "Comma-separated list of data source names")
}
