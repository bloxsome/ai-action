package prwriter

import (
	"context"
	"fmt"

	"github.com/google/go-github/v74/github"
	"github.com/rs/zerolog/log"
)

// PRWriter provides methods to write comments to GitHub pull requests
type PRWriter struct {
	client *github.Client
}

// NewPRWriter creates a new PRWriter with the provided GitHub client
func NewPRWriter(client *github.Client) *PRWriter {
	return &PRWriter{
		client: client,
	}
}

// WriteComment writes a comment to a specific pull request
func (pw *PRWriter) WriteComment(ctx context.Context, owner, repo string, prNumber int, body string) error {
	comment := &github.IssueComment{
		Body: &body,
	}

	log.Info().
		Str("owner", owner).
		Str("repo", repo).
		Int("pr_number", prNumber).
		Msg("Writing comment to pull request")

	_, _, err := pw.client.Issues.CreateComment(ctx, owner, repo, prNumber, comment)
	if err != nil {
		log.Error().Err(err).
			Str("owner", owner).
			Str("repo", repo).
			Int("pr_number", prNumber).
			Msg("Failed to write comment to pull request")
		return fmt.Errorf("failed to write comment to PR #%d: %w", prNumber, err)
	}

	log.Info().
		Str("owner", owner).
		Str("repo", repo).
		Int("pr_number", prNumber).
		Msg("Successfully wrote comment to pull request")

	return nil
}