package filereader

import (
	"context"
	"os"
	"strconv"
	"testing"

	githubclient "ai-action/utils/github-client"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileReader_ReadFile(t *testing.T) {
	privateKey := []byte(os.Getenv("GH_APP_PRIVATE_KEY"))
	appID, _ := strconv.ParseInt(os.Getenv("GH_APP_ID"), 10, 64)
	installationID, _ := strconv.ParseInt(os.Getenv("GH_APP_INSTALLATION_ID"), 10, 64)

	// Create GitHub client
	client, err := githubclient.GetGitHubClient(privateKey, appID, installationID)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Create file reader
	reader := NewFileReader(client)
	require.NotNil(t, reader)

	// Test reading a file from a public repository
	ctx := context.Background()
	content, err := reader.ReadFile(ctx, "EliLillyCo", "ssdlc-action", "README.md", "")

	assert.NoError(t, err)
	assert.NotNil(t, content)
	assert.Greater(t, len(content), 0)
	
	// Check that content contains expected text
	contentStr := string(content)
	assert.Contains(t, contentStr, "ssdlc-action")
}

func TestFileReader_ReadMultipleFiles(t *testing.T) {
	privateKey := []byte(os.Getenv("GH_APP_PRIVATE_KEY"))
	appID, _ := strconv.ParseInt(os.Getenv("GH_APP_ID"), 10, 64)
	installationID, _ := strconv.ParseInt(os.Getenv("GH_APP_INSTALLATION_ID"), 10, 64)

	// Create GitHub client
	client, err := githubclient.GetGitHubClient(privateKey, appID, installationID)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Create file reader
	reader := NewFileReader(client)
	require.NotNil(t, reader)

	// Test reading multiple files from a public repository
	ctx := context.Background()
	paths := []string{"README.md", ".gitignore"}
	files, err := reader.ReadMultipleFiles(ctx, "EliLillyCo", "ssdlc-action", "", paths)

	assert.NoError(t, err)
	assert.NotNil(t, files)
	
	// Should have at least one file (README exists)
	assert.Greater(t, len(files), 0)
	
	// Check README content
	if readmeContent, exists := files["README"]; exists {
		assert.Greater(t, len(readmeContent), 0)
		assert.Contains(t, string(readmeContent), "ssdlc-action")
	}
}

func TestFileReader_ListDirectoryContents(t *testing.T) {
	// Skip test if no GitHub token is available
	privateKey := []byte(os.Getenv("GH_APP_PRIVATE_KEY"))
	appID, _ := strconv.ParseInt(os.Getenv("GH_APP_ID"), 10, 64)
	installationID, _ := strconv.ParseInt(os.Getenv("GH_APP_INSTALLATION_ID"), 10, 64)

	// Create GitHub client
	client, err := githubclient.GetGitHubClient(privateKey, appID, installationID)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Create file reader
	reader := NewFileReader(client)
	require.NotNil(t, reader)

	// Test listing root directory contents
	ctx := context.Background()
	contents, err := reader.ListDirectoryContents(ctx, "EliLillyCo", "ssdlc-action", "", "")

	assert.NoError(t, err)
	assert.NotNil(t, contents)
	assert.Greater(t, len(contents), 0)

	// Should contain README file
	var foundReadme bool
	for _, content := range contents {
		if content.GetName() == "README.md" {
			foundReadme = true
			assert.Equal(t, "file", content.GetType())
			break
		}
	}
	assert.True(t, foundReadme, "Expected to find README.md file in directory listing")
}

func TestFileReader_FileExists(t *testing.T) {
	// Skip test if no GitHub token is available
	privateKey := []byte(os.Getenv("GH_APP_PRIVATE_KEY"))
	appID, _ := strconv.ParseInt(os.Getenv("GH_APP_ID"), 10, 64)
	installationID, _ := strconv.ParseInt(os.Getenv("GH_APP_INSTALLATION_ID"), 10, 64)

	// Create GitHub client
	client, err := githubclient.GetGitHubClient(privateKey, appID, installationID)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Create file reader
	reader := NewFileReader(client)
	require.NotNil(t, reader)

	ctx := context.Background()

	// Test that README exists
	exists, err := reader.FileExists(ctx, "EliLillyCo", "ssdlc-action", "README.md", "")
	assert.NoError(t, err)
	assert.True(t, exists)

	// Test that a non-existent file returns false
	exists, err = reader.FileExists(ctx, "EliLillyCo", "ssdlc-action", "non-existent-file.txt", "")
	assert.NoError(t, err)
	assert.False(t, exists)
}