package claudeclient

import (
	"context"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func TestGetClaudeClient(t *testing.T) {
	client, err := GetClaudeClient()
	assert.NoError(t, err, "Expected no error when initializing Claude client")
	assert.NotNil(t, client, "Expected Claude client to be initialized")

	llm, err := GetLLMClient(client)
	assert.NoError(t, err, "Expected no error when creating LLM client")
	assert.NotNil(t, llm, "Expected LLM client to be initialized")

	prompt := "What is the capital of France?"
	response, err := llm.Call(context.Background(), prompt)

	log.Info().Msgf("LLM Response: %s", response)

	assert.NoError(t, err, "Expected no error when calling LLM")
	assert.NotNil(t, response, "Expected response from LLM")
	assert.Contains(t, response, "Paris", "Expected response to contain 'Paris'")
}
