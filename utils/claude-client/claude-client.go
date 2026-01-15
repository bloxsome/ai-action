package claudeclient

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/rs/zerolog/log"
	"github.com/tmc/langchaingo/llms/bedrock"
)

// GetClaudeClient initializes and returns a Bedrock Runtime client for Claude.
func GetClaudeClient() (*bedrockruntime.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("us-east-1"))
	if err != nil {
		log.Error().Err(err).Msg("Failed to load AWS config")
		return nil, err
	}

	client := bedrockruntime.NewFromConfig(cfg)
	return client, nil
}

// GetLLMClient creates and returns a Bedrock LLM client using the provided Bedrock Runtime client.
func GetLLMClient(client *bedrockruntime.Client) (*bedrock.LLM, error) {
	// Create a new Bedrock LLM with the model that supports direct invocation
	// bedrock.WithModelProvider("anthropic") doesn't exist yet until they make a new release so I can use later versions
	// https://github.com/tmc/langchaingo/issues/1345
	llm, err := bedrock.New(bedrock.WithClient(client), bedrock.WithModel(bedrock.ModelAnthropicClaudeV3Sonnet))
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to create Bedrock LLM")
	}
	return llm, nil
}
