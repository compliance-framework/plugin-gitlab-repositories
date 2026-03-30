package main

import (
	"context"
	"encoding/base64"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

var defaultCodeOwnerPaths = []string{
	"CODEOWNERS",
	".gitlab/CODEOWNERS",
	"docs/CODEOWNERS",
}

// FetchCodeOwners attempts to retrieve the CODEOWNERS file for the project.
// It tries multiple standard locations and returns the decoded file content.
// Returns empty string if the file cannot be found or is inaccessible.
func (l *GitLabReposPlugin) FetchCodeOwners(ctx context.Context, project *gitlab.Project) (string, error) {
	ref := project.DefaultBranch
	if ref == "" {
		ref = "main"
	}

	for _, path := range defaultCodeOwnerPaths {
		file, resp, err := l.client.RepositoryFiles.GetFile(project.ID, path, &gitlab.GetFileOptions{
			Ref: gitlab.Ptr(ref),
		}, gitlab.WithContext(ctx))
		if err != nil {
			if resp != nil && resp.StatusCode == 404 {
				continue
			}
			if isPermissionError(err) {
				return "", nil
			}
			return "", err
		}
		if file == nil {
			continue
		}

		if file.Encoding == "base64" {
			decoded, err := base64.StdEncoding.DecodeString(file.Content)
			if err != nil {
				// Return raw content if decoding fails
				return file.Content, nil
			}
			return string(decoded), nil
		}

		return file.Content, nil
	}

	return "", nil
}
