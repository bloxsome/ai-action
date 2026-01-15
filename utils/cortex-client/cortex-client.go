package cortexclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// CortexClient provides methods to interact with the Cortex API
type CortexClient struct {
	BaseURL    string
	AuthToken  string
	HTTPClient *http.Client
}

// NewCortexClient creates a new Cortex API client
func NewCortexClient(baseURL, authToken string) *CortexClient {
	return &CortexClient{
		BaseURL:   baseURL,
		AuthToken: authToken,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Agent represents a Cortex agent
type Agent struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Model       string   `json:"model,omitempty"`
	Toolkits    []string `json:"toolkits,omitempty"`
	DataSources []string `json:"data_sources,omitempty"`
	Temperature float64  `json:"temperature,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	CreatedAt   string   `json:"created_at,omitempty"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
}

// Toolkit represents a Cortex toolkit
type Toolkit struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tools       []string `json:"tools,omitempty"`
	Owner       string   `json:"owner,omitempty"`
}

// DataSource represents a Cortex data source
type DataSource struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type,omitempty"`
	FileCount   int    `json:"file_count,omitempty"`
	Owner       string `json:"owner,omitempty"`
}

// LLM represents a language model
type LLM struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Provider    string `json:"provider,omitempty"`
	Description string `json:"description,omitempty"`
}

// Prompt represents a Cortex prompt
type Prompt struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Owner   string `json:"owner,omitempty"`
}

// PaginatedResponse represents a paginated API response
type PaginatedResponse struct {
	Items      json.RawMessage `json:"items"`
	TotalCount int             `json:"total_count"`
	Limit      int             `json:"limit"`
	Offset     int             `json:"offset"`
}

// request makes an HTTP request to the Cortex API
func (c *CortexClient) request(ctx context.Context, method, endpoint string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	url := c.BaseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.AuthToken != "" {
		req.Header.Set("Authorization", c.AuthToken)
	}

	log.Debug().
		Str("method", method).
		Str("url", url).
		Msg("Making Cortex API request")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Error().
			Int("status_code", resp.StatusCode).
			Str("response", string(respBody)).
			Msg("Cortex API error")
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// GetAgents retrieves all agents (owned + shared by default)
func (c *CortexClient) GetAgents(ctx context.Context, includeShared bool, limit, offset int) ([]Agent, int, error) {
	endpoint := fmt.Sprintf("/model?limit=%d&offset=%d", limit, offset)

	var agents []Agent
	var totalCount int

	if includeShared {
		// Get owned agents
		ownedResp, err := c.request(ctx, "GET", endpoint+"&is_admin=true", nil)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get owned agents: %w", err)
		}

		var ownedAgents []Agent
		if err := json.Unmarshal(ownedResp, &ownedAgents); err != nil {
			return nil, 0, fmt.Errorf("failed to parse owned agents: %w", err)
		}

		// Get shared agents
		sharedResp, err := c.request(ctx, "GET", endpoint+"&is_admin=false", nil)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get shared agents: %w", err)
		}

		var sharedAgents []Agent
		if err := json.Unmarshal(sharedResp, &sharedAgents); err != nil {
			return nil, 0, fmt.Errorf("failed to parse shared agents: %w", err)
		}

		// Merge and deduplicate
		agentMap := make(map[string]Agent)
		for _, agent := range ownedAgents {
			agentMap[agent.Name] = agent
		}
		for _, agent := range sharedAgents {
			if _, exists := agentMap[agent.Name]; !exists {
				agentMap[agent.Name] = agent
			}
		}

		for _, agent := range agentMap {
			agents = append(agents, agent)
		}
		totalCount = len(agents)
	} else {
		// Only get owned agents
		resp, err := c.request(ctx, "GET", endpoint+"&is_admin=true", nil)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get agents: %w", err)
		}

		if err := json.Unmarshal(resp, &agents); err != nil {
			return nil, 0, fmt.Errorf("failed to parse agents: %w", err)
		}
		totalCount = len(agents)
	}

	log.Info().
		Int("count", len(agents)).
		Int("total", totalCount).
		Bool("include_shared", includeShared).
		Msg("Retrieved agents from Cortex")

	return agents, totalCount, nil
}

// GetAgentDetails retrieves details for a specific agent
func (c *CortexClient) GetAgentDetails(ctx context.Context, agentName string) (*Agent, error) {
	endpoint := fmt.Sprintf("/model/%s", agentName)
	resp, err := c.request(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent details: %w", err)
	}

	var agent Agent
	if err := json.Unmarshal(resp, &agent); err != nil {
		return nil, fmt.Errorf("failed to parse agent details: %w", err)
	}

	return &agent, nil
}

// SearchAgents searches for agents by query
func (c *CortexClient) SearchAgents(ctx context.Context, query string, limit, offset int) ([]Agent, int, error) {
	endpoint := fmt.Sprintf("/model/search?q=%s&limit=%d&offset=%d", query, limit, offset)
	resp, err := c.request(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search agents: %w", err)
	}

	var agents []Agent
	if err := json.Unmarshal(resp, &agents); err != nil {
		return nil, 0, fmt.Errorf("failed to parse search results: %w", err)
	}

	return agents, len(agents), nil
}

// CheckAgentExists checks if an agent with the given name exists
func (c *CortexClient) CheckAgentExists(ctx context.Context, agentName string) (bool, error) {
	_, err := c.GetAgentDetails(ctx, agentName)
	if err != nil {
		if fmt.Sprint(err) == "API request failed with status 404" {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// GetToolkits retrieves all toolkits
func (c *CortexClient) GetToolkits(ctx context.Context, includeShared bool, limit, offset int) ([]Toolkit, int, error) {
	endpoint := fmt.Sprintf("/toolkits?limit=%d&offset=%d", limit, offset)

	var toolkits []Toolkit

	if includeShared {
		endpoint += "&is_admin=false"
	} else {
		endpoint += "&is_admin=true"
	}

	resp, err := c.request(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get toolkits: %w", err)
	}

	if err := json.Unmarshal(resp, &toolkits); err != nil {
		return nil, 0, fmt.Errorf("failed to parse toolkits: %w", err)
	}

	return toolkits, len(toolkits), nil
}

// GetToolkitDetails retrieves details for a specific toolkit
func (c *CortexClient) GetToolkitDetails(ctx context.Context, toolkitName string) (*Toolkit, error) {
	endpoint := fmt.Sprintf("/toolkits/%s", toolkitName)
	resp, err := c.request(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get toolkit details: %w", err)
	}

	var toolkit Toolkit
	if err := json.Unmarshal(resp, &toolkit); err != nil {
		return nil, fmt.Errorf("failed to parse toolkit details: %w", err)
	}

	return &toolkit, nil
}

// GetDataSources retrieves all data sources
func (c *CortexClient) GetDataSources(ctx context.Context, includeShared bool, limit, offset int) ([]DataSource, int, error) {
	endpoint := fmt.Sprintf("/data?limit=%d&offset=%d", limit, offset)

	var dataSources []DataSource

	if includeShared {
		endpoint += "&is_admin=false"
	} else {
		endpoint += "&is_admin=true"
	}

	resp, err := c.request(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get data sources: %w", err)
	}

	if err := json.Unmarshal(resp, &dataSources); err != nil {
		return nil, 0, fmt.Errorf("failed to parse data sources: %w", err)
	}

	return dataSources, len(dataSources), nil
}

// GetDataSourceDetails retrieves details for a specific data source
func (c *CortexClient) GetDataSourceDetails(ctx context.Context, dataSourceName string) (*DataSource, error) {
	endpoint := fmt.Sprintf("/data/%s", dataSourceName)
	resp, err := c.request(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get data source details: %w", err)
	}

	var dataSource DataSource
	if err := json.Unmarshal(resp, &dataSource); err != nil {
		return nil, fmt.Errorf("failed to parse data source details: %w", err)
	}

	return &dataSource, nil
}

// GetLLMList retrieves available LLM models
func (c *CortexClient) GetLLMList(ctx context.Context) ([]LLM, error) {
	endpoint := "/llms"
	resp, err := c.request(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get LLM list: %w", err)
	}

	var llms []LLM
	if err := json.Unmarshal(resp, &llms); err != nil {
		return nil, fmt.Errorf("failed to parse LLM list: %w", err)
	}

	return llms, nil
}

// GetPrompts retrieves all prompts
func (c *CortexClient) GetPrompts(ctx context.Context, limit, offset int) ([]Prompt, int, error) {
	endpoint := fmt.Sprintf("/prompts?limit=%d&offset=%d", limit, offset)
	resp, err := c.request(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get prompts: %w", err)
	}

	var prompts []Prompt
	if err := json.Unmarshal(resp, &prompts); err != nil {
		return nil, 0, fmt.Errorf("failed to parse prompts: %w", err)
	}

	return prompts, len(prompts), nil
}

// GetPromptDetails retrieves details for a specific prompt
func (c *CortexClient) GetPromptDetails(ctx context.Context, promptName string) (*Prompt, error) {
	endpoint := fmt.Sprintf("/prompts/%s", promptName)
	resp, err := c.request(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get prompt details: %w", err)
	}

	var prompt Prompt
	if err := json.Unmarshal(resp, &prompt); err != nil {
		return nil, fmt.Errorf("failed to parse prompt details: %w", err)
	}

	return &prompt, nil
}

// CreateAgent creates a new agent in Cortex
func (c *CortexClient) CreateAgent(ctx context.Context, agent *Agent) error {
	endpoint := "/model"
	_, err := c.request(ctx, "POST", endpoint, agent)
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	log.Info().
		Str("agent_name", agent.Name).
		Msg("Created agent in Cortex")

	return nil
}

// UpdateAgent updates an existing agent
func (c *CortexClient) UpdateAgent(ctx context.Context, agentName string, agent *Agent) error {
	endpoint := fmt.Sprintf("/model/%s", agentName)
	_, err := c.request(ctx, "PUT", endpoint, agent)
	if err != nil {
		return fmt.Errorf("failed to update agent: %w", err)
	}

	log.Info().
		Str("agent_name", agentName).
		Msg("Updated agent in Cortex")

	return nil
}

// DeleteAgent deletes an agent
func (c *CortexClient) DeleteAgent(ctx context.Context, agentName string) error {
	endpoint := fmt.Sprintf("/model/%s", agentName)
	_, err := c.request(ctx, "DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to delete agent: %w", err)
	}

	log.Info().
		Str("agent_name", agentName).
		Msg("Deleted agent from Cortex")

	return nil
}
