package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// setup creates a test HTTP server and a GitLab client pointed at it.
// Retries are disabled so error-path tests complete instantly.
func setup(t *testing.T) (*http.ServeMux, *GitLabReposPlugin) {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client, err := gitlab.NewClient("test-token",
		gitlab.WithBaseURL(server.URL),
		gitlab.WithCustomBackoff(func(_, _ time.Duration, _ int, _ *http.Response) time.Duration {
			return 0
		}),
	)
	if err != nil {
		t.Fatalf("failed to create test client: %v", err)
	}

	plugin := &GitLabReposPlugin{
		Logger: hclog.NewNullLogger(),
		client: client,
		config: &PluginConfig{
			Group:                "test-group",
			pipelineLookbackDays: 90,
		},
	}
	return mux, plugin
}

// writeJSON is a test helper that writes a JSON response with the correct content-type.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(err)
	}
}

func mustReadAll(t *testing.T, r *http.Request) string {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("failed to read request body: %v", err)
	}
	return string(body)
}

func collectProjects(projectChan <-chan *gitlab.Project, errChan <-chan error) ([]*gitlab.Project, error) {
	var projects []*gitlab.Project
	for projectChan != nil || errChan != nil {
		select {
		case project, ok := <-projectChan:
			if !ok {
				projectChan = nil
				continue
			}
			projects = append(projects, project)
		case err, ok := <-errChan:
			if !ok {
				errChan = nil
				continue
			}
			return nil, err
		}
	}
	return projects, nil
}

// ---- pure function tests ----

func TestHasCIConfig(t *testing.T) {
	t.Parallel()

	t.Run("true when last pipeline is non-nil", func(t *testing.T) {
		t.Parallel()
		if !hasCIConfig(&gitlab.Project{}, &gitlab.PipelineInfo{ID: 1}) {
			t.Error("expected true")
		}
	})

	t.Run("true when CIConfigPath is set and no pipeline", func(t *testing.T) {
		t.Parallel()
		if !hasCIConfig(&gitlab.Project{CIConfigPath: ".custom-ci.yml"}, nil) {
			t.Error("expected true")
		}
	})

	t.Run("false when no pipeline and no custom CIConfigPath", func(t *testing.T) {
		t.Parallel()
		if hasCIConfig(&gitlab.Project{}, nil) {
			t.Error("expected false")
		}
	})
}

func TestParseCommaSeparatedList(t *testing.T) {
	t.Parallel()

	got := parseCommaSeparatedList(" repo-a, group/repo-b , ,repo-c ")
	want := []string{"repo-a", "group/repo-b", "repo-c"}
	if len(got) != len(want) {
		t.Fatalf("expected %d items, got %d: %#v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected item %d to be %q, got %q", i, want[i], got[i])
		}
	}
}

func TestIsPermissionError(t *testing.T) {
	t.Parallel()

	t.Run("true for ErrNotFound", func(t *testing.T) {
		t.Parallel()
		if !isPermissionError(gitlab.ErrNotFound) {
			t.Error("expected true for ErrNotFound")
		}
	})

	permissionCodes := []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound}
	for _, code := range permissionCodes {
		code := code
		t.Run(fmt.Sprintf("true for HTTP %d", code), func(t *testing.T) {
			t.Parallel()
			err := &gitlab.ErrorResponse{Response: &http.Response{StatusCode: code}}
			if !isPermissionError(err) {
				t.Errorf("expected true for status %d", code)
			}
		})
	}

	t.Run("false for HTTP 500", func(t *testing.T) {
		t.Parallel()
		err := &gitlab.ErrorResponse{Response: &http.Response{StatusCode: http.StatusInternalServerError}}
		if isPermissionError(err) {
			t.Error("expected false for 500")
		}
	})

	t.Run("false for nil error", func(t *testing.T) {
		t.Parallel()
		if isPermissionError(nil) {
			t.Error("expected false for nil")
		}
	})

	t.Run("false for non-GitLab error", func(t *testing.T) {
		t.Parallel()
		if isPermissionError(fmt.Errorf("some other error")) {
			t.Error("expected false for generic error")
		}
	})
}

// ---- buildGitLabClient ----

func TestBuildGitLabClient_PAT(t *testing.T) {
	t.Parallel()
	plugin := &GitLabReposPlugin{Logger: hclog.NewNullLogger()}
	config := &PluginConfig{AuthType: AuthTypePAT, Token: "test-token"}
	client, err := plugin.buildGitLabClient(config, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestBuildGitLabClient_OAuth(t *testing.T) {
	t.Parallel()
	plugin := &GitLabReposPlugin{Logger: hclog.NewNullLogger()}
	config := &PluginConfig{AuthType: AuthTypeOAuth, Token: "bearer-token"}
	client, err := plugin.buildGitLabClient(config, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestBuildGitLabClient_ClientCredentials(t *testing.T) {
	t.Parallel()

	// Stand up a mock OAuth token endpoint.
	var (
		requestPath  string
		requestScope string
	)
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		body, err := url.ParseQuery(mustReadAll(t, r))
		if err != nil {
			t.Fatalf("failed to parse token request body: %v", err)
		}
		requestScope = body.Get("scope")

		if r.URL.Path != "/oauth/token" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]any{
			"access_token": "fetched-token",
			"token_type":   "bearer",
			"expires_in":   7200,
		})
	}))
	t.Cleanup(tokenServer.Close)

	plugin := &GitLabReposPlugin{Logger: hclog.NewNullLogger()}
	config := &PluginConfig{
		AuthType:     AuthTypeClientCredentials,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Scopes:       "api, read_user , ",
		BaseURL:      tokenServer.URL + "/",
	}
	opts := []gitlab.ClientOptionFunc{gitlab.WithBaseURL(tokenServer.URL)}

	client, err := plugin.buildGitLabClient(config, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if requestPath != "/oauth/token" {
		t.Fatalf("expected token path /oauth/token, got %q", requestPath)
	}
	if requestScope != "api read_user" {
		t.Fatalf("expected normalized scope %q, got %q", "api read_user", requestScope)
	}
}

func TestBuildGitLabClient_ClientCredentials_InvalidToken(t *testing.T) {
	t.Parallel()

	// Token endpoint returns 401.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
	}))
	t.Cleanup(tokenServer.Close)

	plugin := &GitLabReposPlugin{Logger: hclog.NewNullLogger()}
	config := &PluginConfig{
		AuthType:     AuthTypeClientCredentials,
		ClientID:     "bad-id",
		ClientSecret: "bad-secret",
		BaseURL:      tokenServer.URL,
	}

	_, err := plugin.buildGitLabClient(config, nil)
	if err == nil {
		t.Fatal("expected error for invalid credentials, got nil")
	}
}

func TestBuildGitLabClient_UnknownAuthType(t *testing.T) {
	t.Parallel()
	plugin := &GitLabReposPlugin{Logger: hclog.NewNullLogger()}
	config := &PluginConfig{AuthType: "magic"}
	_, err := plugin.buildGitLabClient(config, nil)
	if err == nil {
		t.Fatal("expected error for unknown auth_type")
	}
}

func TestResolveConfiguredGroup_UsesResolvedIDForProjectCalls(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)
	plugin.config.Group = "parent/subgroup"

	mux.HandleFunc("/api/v4/groups/parent%2Fsubgroup", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"id":        123,
			"name":      "subgroup",
			"path":      "subgroup",
			"full_path": "parent/subgroup",
		})
	})

	var requestedPath string
	mux.HandleFunc("/api/v4/groups/123/projects", func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		writeJSON(w, []map[string]any{
			{"id": 1, "name": "repo", "path": "repo", "path_with_namespace": "parent/subgroup/repo"},
		})
	})

	if err := plugin.resolveConfiguredGroup(context.Background()); err != nil {
		t.Fatalf("unexpected resolve error: %v", err)
	}
	if plugin.resolvedGroupID != 123 {
		t.Fatalf("expected resolved group ID 123, got %d", plugin.resolvedGroupID)
	}

	projects, err := collectProjects(plugin.FetchProjects(context.Background()))
	if err != nil {
		t.Fatalf("unexpected fetch projects error: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("expected 1 project, got %d", len(projects))
	}
	if requestedPath != "/api/v4/groups/123/projects" {
		t.Fatalf("expected projects endpoint to use resolved numeric group ID, got %q", requestedPath)
	}
}

func TestResolveConfiguredGroup_NotFoundReturnsHelpfulError(t *testing.T) {
	t.Parallel()
	_, plugin := setup(t)
	plugin.config.Group = "platform"

	err := plugin.resolveConfiguredGroup(context.Background())
	if err == nil {
		t.Fatal("expected resolveConfiguredGroup to fail")
	}
	if !strings.Contains(err.Error(), "numeric ID or full path") {
		t.Fatalf("expected helpful error about numeric ID or full path, got %q", err.Error())
	}
}

// ---- FetchLastPipelineRun ----

func TestFetchLastPipelineRun_Found(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)

	mux.HandleFunc("/api/v4/projects/1/pipelines", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []map[string]any{
			{"id": 42, "status": "success", "ref": "main", "updated_at": "2024-01-15T10:00:00Z"},
		})
	})

	pipeline, err := plugin.FetchLastPipelineRun(context.Background(), &gitlab.Project{ID: 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pipeline == nil {
		t.Fatal("expected non-nil pipeline")
	}
	if pipeline.ID != 42 {
		t.Errorf("expected pipeline ID 42, got %d", pipeline.ID)
	}
	if pipeline.Status != "success" {
		t.Errorf("expected status 'success', got %q", pipeline.Status)
	}
}

func TestFetchLastPipelineRun_NoPipelines(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)

	mux.HandleFunc("/api/v4/projects/1/pipelines", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []any{})
	})

	pipeline, err := plugin.FetchLastPipelineRun(context.Background(), &gitlab.Project{ID: 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pipeline != nil {
		t.Errorf("expected nil pipeline, got %+v", pipeline)
	}
}

func TestFetchLastPipelineRun_PermissionError(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)

	mux.HandleFunc("/api/v4/projects/1/pipelines", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"403 Forbidden"}`, http.StatusForbidden)
	})

	pipeline, err := plugin.FetchLastPipelineRun(context.Background(), &gitlab.Project{ID: 1})
	if err != nil {
		t.Fatalf("expected nil error for permission error, got %v", err)
	}
	if pipeline != nil {
		t.Error("expected nil pipeline for permission error")
	}
}

// ---- GatherPipelineRuns ----

func TestGatherPipelineRuns_ReturnsRuns(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)

	mux.HandleFunc("/api/v4/projects/1/pipelines", func(w http.ResponseWriter, r *http.Request) {
		// Verify the lookback filter is sent.
		if r.URL.Query().Get("updated_after") == "" {
			t.Error("expected updated_after query param to be set")
		}
		writeJSON(w, []map[string]any{
			{"id": 10, "status": "success", "ref": "main"},
			{"id": 11, "status": "failed", "ref": "main"},
			{"id": 12, "status": "failed", "ref": "feature"},
		})
	})

	runs, err := plugin.GatherPipelineRuns(context.Background(), &gitlab.Project{ID: 1, PathWithNamespace: "grp/proj"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(runs) != 3 {
		t.Errorf("expected 3 runs, got %d", len(runs))
	}

	failed := 0
	for _, r := range runs {
		if r.Status == "failed" {
			failed++
		}
	}
	if failed != 2 {
		t.Errorf("expected 2 failed runs, got %d", failed)
	}
}

func TestGatherGroupMembers_PermissionError(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)
	plugin.config.Group = "parent/subgroup"

	mux.HandleFunc("/api/v4/groups/parent%2Fsubgroup", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"id":        123,
			"name":      "subgroup",
			"path":      "subgroup",
			"full_path": "parent/subgroup",
		})
	})
	mux.HandleFunc("/api/v4/groups/123/members/all", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"403 Forbidden"}`, http.StatusForbidden)
	})

	if err := plugin.resolveConfiguredGroup(context.Background()); err != nil {
		t.Fatalf("unexpected resolve error: %v", err)
	}

	members, err := plugin.GatherGroupMembers(context.Background())
	if err != nil {
		t.Fatalf("expected nil error for permission error, got %v", err)
	}
	if members != nil {
		t.Error("expected nil members for permission error")
	}
}

func TestGatherGroupMembers_NotFoundAfterResolution(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)
	plugin.config.Group = "parent/subgroup"

	mux.HandleFunc("/api/v4/groups/parent%2Fsubgroup", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"id":        123,
			"name":      "subgroup",
			"path":      "subgroup",
			"full_path": "parent/subgroup",
		})
	})

	if err := plugin.resolveConfiguredGroup(context.Background()); err != nil {
		t.Fatalf("unexpected resolve error: %v", err)
	}

	members, err := plugin.GatherGroupMembers(context.Background())
	if err != nil {
		t.Fatalf("expected nil error for not found, got %v", err)
	}
	if members != nil {
		t.Error("expected nil members for not found")
	}
}

func TestGatherGroupMembers_ServerError(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)
	plugin.config.Group = "parent/subgroup"

	mux.HandleFunc("/api/v4/groups/parent%2Fsubgroup", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"id":        123,
			"name":      "subgroup",
			"path":      "subgroup",
			"full_path": "parent/subgroup",
		})
	})
	mux.HandleFunc("/api/v4/groups/123/members/all", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"500 Internal Server Error"}`, http.StatusInternalServerError)
	})

	if err := plugin.resolveConfiguredGroup(context.Background()); err != nil {
		t.Fatalf("unexpected resolve error: %v", err)
	}

	members, err := plugin.GatherGroupMembers(context.Background())
	if err == nil {
		t.Fatal("expected error for server error, got nil")
	}
	if members != nil {
		t.Error("expected nil members when request fails")
	}
}

func TestGatherPipelineRuns_PermissionError(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)

	mux.HandleFunc("/api/v4/projects/1/pipelines", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"403 Forbidden"}`, http.StatusForbidden)
	})

	runs, err := plugin.GatherPipelineRuns(context.Background(), &gitlab.Project{ID: 1, PathWithNamespace: "grp/proj"})
	if err != nil {
		t.Fatalf("expected nil error for permission error, got %v", err)
	}
	if runs != nil {
		t.Error("expected nil runs for permission error")
	}
}

// ---- FetchCodeOwners ----

func TestFetchCodeOwners_FoundAtRootPath(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)

	content := "* @team-lead\n/src/ @backend-team\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(content))

	mux.HandleFunc("/api/v4/projects/1/repository/files/CODEOWNERS", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"file_name": "CODEOWNERS",
			"encoding":  "base64",
			"content":   encoded,
		})
	})

	result, err := plugin.FetchCodeOwners(context.Background(), &gitlab.Project{ID: 1, DefaultBranch: "main"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != content {
		t.Errorf("expected %q, got %q", content, result)
	}
}

func TestFetchCodeOwners_NotFound(t *testing.T) {
	t.Parallel()
	_, plugin := setup(t)

	// No handlers registered — mux returns 404 for all paths.
	result, err := plugin.FetchCodeOwners(context.Background(), &gitlab.Project{ID: 1, DefaultBranch: "main"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestFetchCodeOwners_DefaultBranchFallback(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)

	var receivedRef string
	mux.HandleFunc("/api/v4/projects/1/repository/files/CODEOWNERS", func(w http.ResponseWriter, r *http.Request) {
		receivedRef = r.URL.Query().Get("ref")
		writeJSON(w, map[string]any{
			"file_name": "CODEOWNERS",
			"encoding":  "base64",
			"content":   base64.StdEncoding.EncodeToString([]byte("* @owner")),
		})
	})

	// DefaultBranch is empty — should fall back to "main".
	_, err := plugin.FetchCodeOwners(context.Background(), &gitlab.Project{ID: 1, DefaultBranch: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedRef != "main" {
		t.Errorf("expected ref 'main', got %q", receivedRef)
	}
}

func TestFetchCodeOwners_InvalidBase64ReturnsError(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)

	mux.HandleFunc("/api/v4/projects/1/repository/files/CODEOWNERS", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"file_name": "CODEOWNERS",
			"encoding":  "base64",
			"content":   "!!!not-base64!!!",
		})
	})

	result, err := plugin.FetchCodeOwners(context.Background(), &gitlab.Project{ID: 1, DefaultBranch: "main"})
	if err == nil {
		t.Fatal("expected error for invalid base64 content")
	}
	if result != "" {
		t.Fatalf("expected empty result on decode error, got %q", result)
	}
}

// ---- GatherOpenMergeRequests ----

func TestGatherOpenMergeRequests_WithApprovals(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)

	mux.HandleFunc("/api/v4/projects/1/merge_requests", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != "opened" {
			t.Errorf("expected state=opened, got %q", r.URL.Query().Get("state"))
		}
		writeJSON(w, []map[string]any{
			{"id": 101, "iid": 1, "title": "Fix bug", "state": "opened"},
			{"id": 102, "iid": 2, "title": "Add feature", "state": "opened"},
		})
	})

	mux.HandleFunc("/api/v4/projects/1/merge_requests/1/approval_state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"approval_rules_overwritten": false,
			"rules": []map[string]any{
				{"id": 1, "name": "Default", "approvals_required": 2, "approved": false},
			},
		})
	})

	mux.HandleFunc("/api/v4/projects/1/merge_requests/2/approval_state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"approval_rules_overwritten": false,
			"rules": []map[string]any{
				{"id": 1, "name": "Default", "approvals_required": 1, "approved": true},
			},
		})
	})

	mrs, err := plugin.GatherOpenMergeRequests(context.Background(), &gitlab.Project{ID: 1, PathWithNamespace: "grp/proj"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mrs) != 2 {
		t.Fatalf("expected 2 MRs, got %d", len(mrs))
	}

	// First MR should not be approved.
	if mrs[0].ApprovalState == nil {
		t.Fatal("expected non-nil approval state for MR 1")
	}
	if mrs[0].ApprovalState.Rules[0].Approved {
		t.Error("expected MR 1 to not be approved")
	}

	// Second MR should be approved.
	if mrs[1].ApprovalState == nil {
		t.Fatal("expected non-nil approval state for MR 2")
	}
	if !mrs[1].ApprovalState.Rules[0].Approved {
		t.Error("expected MR 2 to be approved")
	}
}

func TestFetchProjects_TrimsRepositoryFilters(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)
	plugin.config.IncludedRepositories = " repo-a, repo-b "

	mux.HandleFunc("/api/v4/groups/test-group/projects", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []map[string]any{
			{"id": 1, "name": "repo-a", "path": "repo-a", "path_with_namespace": "group/repo-a"},
			{"id": 2, "name": "repo-b", "path": "repo-b", "path_with_namespace": "group/repo-b"},
			{"id": 3, "name": "repo-c", "path": "repo-c", "path_with_namespace": "group/repo-c"},
		})
	})

	projects, err := collectProjects(plugin.FetchProjects(context.Background()))
	if err != nil {
		t.Fatalf("unexpected fetch projects error: %v", err)
	}
	if len(projects) != 2 {
		t.Fatalf("expected 2 matching projects, got %d", len(projects))
	}
	if projects[0].Name != "repo-a" {
		t.Fatalf("expected first project repo-a, got %q", projects[0].Name)
	}
	if projects[1].Path != "repo-b" {
		t.Fatalf("expected second project path repo-b, got %q", projects[1].Path)
	}
}

func TestGatherOpenMergeRequests_PermissionError(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)

	mux.HandleFunc("/api/v4/projects/1/merge_requests", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"403 Forbidden"}`, http.StatusForbidden)
	})

	mrs, err := plugin.GatherOpenMergeRequests(context.Background(), &gitlab.Project{ID: 1, PathWithNamespace: "grp/proj"})
	if err != nil {
		t.Fatalf("expected nil error for permission error, got %v", err)
	}
	if mrs != nil {
		t.Error("expected nil MRs for permission error")
	}
}

// ---- GatherProtectedBranches ----

func TestGatherProtectedBranches(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)

	mux.HandleFunc("/api/v4/projects/1/protected_branches", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []map[string]any{
			{
				"id":   1,
				"name": "main",
				"push_access_levels": []map[string]any{
					{"access_level": 40, "access_level_description": "Maintainers"},
				},
				"merge_access_levels": []map[string]any{
					{"access_level": 30, "access_level_description": "Developers + Maintainers"},
				},
				"allow_force_push":             false,
				"code_owner_approval_required": true,
			},
		})
	})

	branches, err := plugin.GatherProtectedBranches(context.Background(), &gitlab.Project{ID: 1, PathWithNamespace: "grp/proj"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(branches) != 1 {
		t.Fatalf("expected 1 branch, got %d", len(branches))
	}
	if branches[0].Name != "main" {
		t.Errorf("expected branch name 'main', got %q", branches[0].Name)
	}
	if !branches[0].CodeOwnerApprovalRequired {
		t.Error("expected code_owner_approval_required to be true")
	}
}

// ---- FetchLatestRelease ----

func TestFetchLatestRelease_Found(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)

	mux.HandleFunc("/api/v4/projects/1/releases", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []map[string]any{
			{"tag_name": "v1.2.3", "name": "Version 1.2.3", "released_at": "2024-06-01T00:00:00Z"},
		})
	})

	release, err := plugin.FetchLatestRelease(context.Background(), &gitlab.Project{ID: 1, PathWithNamespace: "grp/proj"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if release == nil {
		t.Fatal("expected non-nil release")
	}
	if release.TagName != "v1.2.3" {
		t.Errorf("expected tag 'v1.2.3', got %q", release.TagName)
	}
}

func TestFetchLatestRelease_NoReleases(t *testing.T) {
	t.Parallel()
	mux, plugin := setup(t)

	mux.HandleFunc("/api/v4/projects/1/releases", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []any{})
	})

	release, err := plugin.FetchLatestRelease(context.Background(), &gitlab.Project{ID: 1, PathWithNamespace: "grp/proj"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if release != nil {
		t.Errorf("expected nil release, got %+v", release)
	}
}
