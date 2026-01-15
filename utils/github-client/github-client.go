package githubclient

import (
	"context"

	"github.com/google/go-github/v74/github"
	"github.com/jferrl/go-githubauth"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

// GetGitHubClient initializes and returns a GitHub client with authentication.
func GetGitHubClient(privateKey []byte, appID int64, installationID int64) (*github.Client, error) {
	appTokenSource, err := githubauth.NewApplicationTokenSource(appID, privateKey)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create application token source")
		return nil, err
	}

	installationTokenSource := githubauth.NewInstallationTokenSource(installationID, appTokenSource)

	// oauth2.NewClient create a new http.Client that adds an Authorization header with the token.
	// Transport src use oauth2.ReuseTokenSource to reuse the token.
	// The token will be reused until it expires.
	// The token will be refreshed if it's expired.
	httpClient := oauth2.NewClient(context.Background(), installationTokenSource)

	githubClient := github.NewClient(httpClient)

	return githubClient, nil
}

// GetGitHubClientPAT initializes and returns a GitHub client with a personal access token.
func GetGitHubClientPAT(token string) *github.Client {
	return github.NewClient(nil).WithAuthToken(token)
}