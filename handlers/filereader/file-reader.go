package filereader

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/go-github/v74/github"
	"github.com/rs/zerolog/log"

	aiHandler "ai-action/handlers/ai"
)

// FileReader provides methods to read files from GitHub repositories
type FileReader struct {
	client *github.Client
}

// NewFileReader creates a new FileReader with the provided GitHub client
func NewFileReader(client *github.Client) *FileReader {
	return &FileReader{
		client: client,
	}
}

// ReadFile reads a file from a GitHub repository
func (fr *FileReader) ReadFile(ctx context.Context, owner, repo, path, ref string) ([]byte, error) {
	opts := &github.RepositoryContentGetOptions{}
	if ref != "" {
		opts.Ref = ref
	}

	fileContent, _, _, err := fr.client.Repositories.GetContents(ctx, owner, repo, path, opts)
	if err != nil {
		log.Error().Err(err).
			Str("owner", owner).
			Str("repo", repo).
			Str("path", path).
			Str("ref", ref).
			Msg("Failed to get file content from GitHub")
		return nil, fmt.Errorf("failed to get file content: %w", err)
	}

	if fileContent == nil {
		return nil, fmt.Errorf("file not found: %s", path)
	}

	content, err := fileContent.GetContent()
	if err != nil {
		log.Error().Err(err).
			Str("path", path).
			Msg("Failed to decode file content")
		return nil, fmt.Errorf("failed to decode file content: %w", err)
	}

	return []byte(content), nil
}

// ReadMultipleFiles reads multiple files from a GitHub repository
func (fr *FileReader) ReadMultipleFiles(ctx context.Context, owner, repo, ref string, paths []string) (map[string][]byte, error) {
	files := make(map[string][]byte)
	
	for _, path := range paths {
		content, err := fr.ReadFile(ctx, owner, repo, path, ref)
		if err != nil {
			log.Warn().Err(err).
				Str("path", path).
				Msg("Failed to read file, skipping")
			continue
		}
		files[path] = content
	}

	return files, nil
}

// ListDirectoryContents lists the contents of a directory in a GitHub repository
func (fr *FileReader) ListDirectoryContents(ctx context.Context, owner, repo, path, ref string) ([]*github.RepositoryContent, error) {
	opts := &github.RepositoryContentGetOptions{}
	if ref != "" {
		opts.Ref = ref
	}

	_, directoryContent, _, err := fr.client.Repositories.GetContents(ctx, owner, repo, path, opts)
	if err != nil {
		log.Error().Err(err).
			Str("owner", owner).
			Str("repo", repo).
			Str("path", path).
			Str("ref", ref).
			Msg("Failed to get directory contents from GitHub")
		return nil, fmt.Errorf("failed to get directory contents: %w", err)
	}

	return directoryContent, nil
}

// FileExists checks if a file exists in a GitHub repository
func (fr *FileReader) FileExists(ctx context.Context, owner, repo, path, ref string) (bool, error) {
	opts := &github.RepositoryContentGetOptions{}
	if ref != "" {
		opts.Ref = ref
	}

	_, _, _, err := fr.client.Repositories.GetContents(ctx, owner, repo, path, opts)
	if err != nil {
		if githubErr, ok := err.(*github.ErrorResponse); ok && githubErr.Response.StatusCode == 404 {
			return false, nil
		}
		log.Error().Err(err).
			Str("owner", owner).
			Str("repo", repo).
			Str("path", path).
			Str("ref", ref).
			Msg("Failed to check if file exists")
		return false, fmt.Errorf("failed to check file existence: %w", err)
	}

	return true, nil
}

// GetRepositoryFiles fetches files from the repository based on specified criteria
func (fr *FileReader) GetRepositoryFiles(ctx context.Context, owner, repo, ref, pathsFilter string, maxFiles int) ([]aiHandler.FileContext, error) {
	var files []aiHandler.FileContext

	// Get directory contents (start with root)
	contents, err := fr.ListDirectoryContents(ctx, owner, repo, "", ref)
	if err != nil {
		return nil, fmt.Errorf("failed to list repository contents: %w", err)
	}

	// Parse path filters
	var filters []string
	if pathsFilter != "" {
		filters = strings.Split(pathsFilter, ",")
		for i, filter := range filters {
			filters[i] = strings.TrimSpace(filter)
		}
	}

	// Recursively collect files
	err = fr.collectFiles(ctx, owner, repo, ref, "", contents, filters, maxFiles, &files)
	if err != nil {
		return nil, fmt.Errorf("failed to collect files: %w", err)
	}

	return files, nil
}

// collectFiles recursively collects files from the repository
func (fr *FileReader) collectFiles(ctx context.Context, owner, repo, ref, currentPath string, contents []*github.RepositoryContent, filters []string, maxFiles int, files *[]aiHandler.FileContext) error {
	for _, content := range contents {
		if len(*files) >= maxFiles {
			log.Info().Int("max_files", maxFiles).Msg("Reached maximum file limit")
			break
		}

		path := content.GetPath()
		if currentPath != "" {
			path = filepath.Join(currentPath, content.GetName())
		}

		if content.GetType() == "file" {
			// Check if file matches filters
			if fr.shouldIncludeFile(path, filters) {
				log.Info().Str("path", path).Msg("Reading file")

				fileContent, err := fr.ReadFile(ctx, owner, repo, path, ref)
				if err != nil {
					log.Warn().Err(err).Str("path", path).Msg("Failed to read file, skipping")
					continue
				}

				fileCtx := aiHandler.CreateFileContextFromContent(path, string(fileContent))
				*files = append(*files, fileCtx)
			}
		} else if content.GetType() == "dir" {
			// Recursively process directories
			dirContents, err := fr.ListDirectoryContents(ctx, owner, repo, path, ref)
			if err != nil {
				log.Warn().Err(err).Str("path", path).Msg("Failed to list directory, skipping")
				continue
			}

			err = fr.collectFiles(ctx, owner, repo, ref, path, dirContents, filters, maxFiles, files)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// shouldIncludeFile determines if a file should be included based on filters
func (fr *FileReader) shouldIncludeFile(path string, filters []string) bool {
	// If no filters specified, include common code files
	if len(filters) == 0 {
		ext := strings.ToLower(filepath.Ext(path))
		commonCodeExts := []string{".go", ".js", ".ts", ".py", ".java", ".cpp", ".c", ".rs", ".rb", ".php", ".cs", ".kt", ".swift", ".scala"}
		for _, codeExt := range commonCodeExts {
			if ext == codeExt {
				return true
			}
		}
		return false
	}

	// Check against filters
	for _, filter := range filters {
		if matched, _ := filepath.Match(filter, filepath.Base(path)); matched {
			return true
		}
		// Also check full path for patterns like "src/*.go"
		if matched, _ := filepath.Match(filter, path); matched {
			return true
		}
	}

	return false
}