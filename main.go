package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/mitchellh/mapstructure"
	gitlab "gitlab.com/gitlab-org/api/client-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type Validator interface {
	Validate() error
}

// AuthType values
const (
	AuthTypePAT               = "pat"                // Personal Access Token (default)
	AuthTypeOAuth             = "oauth"              // Pre-obtained OAuth / OIDC Bearer token
	AuthTypeClientCredentials = "client_credentials" // OAuth 2.0 client credentials grant
)

type PluginConfig struct {
	// AuthType selects the authentication method. One of: "pat" (default), "oauth", "client_credentials".
	AuthType string `mapstructure:"auth_type"`

	// Token is a Personal Access Token (auth_type=pat) or a pre-obtained OAuth/OIDC Bearer token (auth_type=oauth).
	Token string `mapstructure:"token"`

	// ClientID and ClientSecret are used with auth_type=client_credentials to obtain a token
	// from GitLab's OAuth token endpoint via the client_credentials grant.
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`

	// Scopes is a comma-separated list of OAuth scopes requested with the token.
	// Required for auth_type=client_credentials. GitLab applications typically
	// need "api" (full access) or "read_api" (read-only). The scopes must match
	// those granted to the GitLab Application when it was created.
	// Example: "api" or "read_api,read_user"
	Scopes string `mapstructure:"scopes"`

	// Group must be either the numeric GitLab group ID or the full group path
	// (for example "parent/subgroup"). Short display names are not sufficient.
	Group                string `mapstructure:"group"`
	BaseURL              string `mapstructure:"base_url"`               // optional: self-hosted GitLab instance URL
	IncludedRepositories string `mapstructure:"included_repositories"`  // comma-separated project names or paths
	ExcludedRepositories string `mapstructure:"excluded_repositories"`  // comma-separated project names or paths
	PipelineLookbackDays string `mapstructure:"pipeline_lookback_days"` // Number of days to look back for pipelines (default: 90)

	// Parsed values (set during Configure)
	pipelineLookbackDays int
}

func (c *PluginConfig) Validate() error {
	// Normalise: empty auth_type defaults to PAT for backwards compatibility.
	if c.AuthType == "" {
		c.AuthType = AuthTypePAT
	}

	switch c.AuthType {
	case AuthTypePAT, AuthTypeOAuth:
		if c.Token == "" {
			return fmt.Errorf("token is required for auth_type=%q", c.AuthType)
		}
	case AuthTypeClientCredentials:
		if c.ClientID == "" {
			return fmt.Errorf("client_id is required for auth_type=%q", c.AuthType)
		}
		if c.ClientSecret == "" {
			return fmt.Errorf("client_secret is required for auth_type=%q", c.AuthType)
		}
		if c.Scopes == "" {
			return fmt.Errorf("scopes is required for auth_type=%q (e.g. \"api\" or \"read_api\")", c.AuthType)
		}
	default:
		return fmt.Errorf("unknown auth_type %q; must be one of: pat, oauth, client_credentials", c.AuthType)
	}

	if c.Group == "" {
		return fmt.Errorf("group is required")
	}
	if c.IncludedRepositories != "" && c.ExcludedRepositories != "" {
		return fmt.Errorf("only one of included_repositories or excluded_repositories may be set")
	}
	return nil
}

func (c *PluginConfig) parsePipelineConfig() error {
	if c.PipelineLookbackDays == "" {
		c.pipelineLookbackDays = 90
	} else {
		days, err := strconv.Atoi(c.PipelineLookbackDays)
		if err != nil {
			return fmt.Errorf("invalid pipeline_lookback_days: %w", err)
		}
		c.pipelineLookbackDays = days
	}
	return nil
}

type GitLabReposPlugin struct {
	Logger hclog.Logger

	config          *PluginConfig
	client          *gitlab.Client
	resolvedGroupID int64
}

func (l *GitLabReposPlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.Logger.Info("Configuring GitLab Repositories Plugin")
	config := &PluginConfig{}

	if err := mapstructure.Decode(req.Config, config); err != nil {
		l.Logger.Error("Error decoding config", "error", err)
		return nil, err
	}

	if err := config.Validate(); err != nil {
		l.Logger.Error("Error validating config", "error", err)
		return nil, err
	}

	if err := config.parsePipelineConfig(); err != nil {
		l.Logger.Error("Error parsing pipeline config", "error", err)
		return nil, err
	}

	l.config = config

	opts := []gitlab.ClientOptionFunc{}
	if config.BaseURL != "" {
		opts = append(opts, gitlab.WithBaseURL(config.BaseURL))
	}

	client, err := l.buildGitLabClient(config, opts)
	if err != nil {
		return nil, err
	}
	l.client = client

	if err := l.resolveConfiguredGroup(context.Background()); err != nil {
		l.Logger.Error("Error resolving configured group", "group", config.Group, "error", err)
		return nil, err
	}

	return &proto.ConfigureResponse{}, nil
}

// buildGitLabClient creates a GitLab API client using the configured authentication method.
//
//   - pat:                Personal Access Token — uses AccessTokenAuthSource (PRIVATE-TOKEN header).
//   - oauth:              Pre-obtained OAuth / OIDC Bearer token — wraps it in a StaticTokenSource
//     so the Authorization: Bearer header is set on every request.
//   - client_credentials: Fetches tokens from GitLab's OAuth endpoint via the client_credentials
//     grant and wraps the resulting TokenSource in OAuthTokenSource so tokens are refreshed
//     automatically as they expire during long evaluation runs.
func (l *GitLabReposPlugin) buildGitLabClient(config *PluginConfig, opts []gitlab.ClientOptionFunc) (*gitlab.Client, error) {
	switch config.AuthType {
	case AuthTypePAT:
		// NewClient internally uses AccessTokenAuthSource (PRIVATE-TOKEN header) — not deprecated.
		client, err := gitlab.NewClient(config.Token, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create GitLab PAT client: %w", err)
		}
		return client, nil

	case AuthTypeOAuth:
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: config.Token})
		client, err := gitlab.NewAuthSourceClient(gitlab.OAuthTokenSource{TokenSource: ts}, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create GitLab OAuth client: %w", err)
		}
		return client, nil

	case AuthTypeClientCredentials:
		tokenURL := config.BaseURL + "/oauth/token"
		if config.BaseURL == "" {
			tokenURL = "https://gitlab.com/oauth/token"
		}

		ccConfig := &clientcredentials.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			TokenURL:     tokenURL,
			Scopes:       strings.Split(config.Scopes, ","),
		}

		// TokenSource is lazy — eagerly call Token() once to validate the credentials
		// before we hand the client back to the caller.
		ts := ccConfig.TokenSource(context.Background())
		if _, err := ts.Token(); err != nil {
			return nil, fmt.Errorf("failed to obtain OAuth token via client_credentials grant: %w", err)
		}

		// OAuthTokenSource calls ts.Token() on every request, so expired tokens are
		// refreshed automatically without any extra plumbing.
		client, err := gitlab.NewAuthSourceClient(gitlab.OAuthTokenSource{TokenSource: ts}, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create GitLab client_credentials client: %w", err)
		}
		return client, nil

	default:
		return nil, fmt.Errorf("unsupported auth_type: %s", config.AuthType)
	}
}

func (l *GitLabReposPlugin) groupRef() any {
	if l.resolvedGroupID != 0 {
		return l.resolvedGroupID
	}
	return l.config.Group
}

func (l *GitLabReposPlugin) resolveConfiguredGroup(ctx context.Context) error {
	group, _, err := l.client.Groups.GetGroup(l.config.Group, nil, gitlab.WithContext(ctx))
	if err != nil {
		if isPermissionError(err) {
			return fmt.Errorf("could not resolve configured group %q: group must be a numeric ID or full path, and the token identity must be able to see it", l.config.Group)
		}
		return fmt.Errorf("could not resolve configured group %q: %w", l.config.Group, err)
	}
	if group == nil || group.ID == 0 {
		return fmt.Errorf("could not resolve configured group %q: GitLab returned an empty group response", l.config.Group)
	}

	l.resolvedGroupID = group.ID
	l.Logger.Debug("Resolved configured group", "configured_group", l.config.Group, "group_id", group.ID, "full_path", group.FullPath)
	return nil
}

func (l *GitLabReposPlugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	ctx := context.Background()

	subjectTemplates := []*proto.SubjectTemplate{
		{
			Name:                "gitlab-repository",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       "GitLab Repository: {{ .repository }}",
			DescriptionTemplate: "GitLab repository {{ .repository }} in group {{ .group }}",
			PurposeTemplate:     "Represents a GitLab repository being monitored for compliance",
			IdentityLabelKeys:   []string{"repository", "group"},
			SelectorLabels:      []*proto.SubjectLabelSelector{},
			LabelSchema: []*proto.SubjectLabelSchema{
				{Key: "repository", Description: "The path of the GitLab repository"},
				{Key: "group", Description: "The GitLab group owning the repository"},
			},
		},
	}

	return runner.InitWithSubjectsAndRisksFromPolicies(ctx, l.Logger, req, apiHelper, subjectTemplates)
}

func (l *GitLabReposPlugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()

	groupMembers, err := l.GatherGroupMembers(ctx)
	if err != nil {
		l.Logger.Error("Error gathering group members", "error", err)
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
	}

	projectChan, errChan := l.FetchProjects(ctx)
	done := false

	for !done {
		select {
		case err, ok := <-errChan:
			if !ok {
				done = true
				continue
			}
			l.Logger.Error("Error fetching projects", "error", err)
			return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err

		case project, ok := <-projectChan:
			if !ok {
				done = true
				continue
			}

			l.Logger.Debug("Processing project", "project", project.PathWithNamespace, "default_branch", project.DefaultBranch, "visibility", project.Visibility)

			protectedBranches, err := l.GatherProtectedBranches(ctx, project)
			if err != nil {
				l.Logger.Error("Error gathering protected branches", "project", project.PathWithNamespace, "error", err)
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
			}
			l.Logger.Debug("Gathered protected branches", "project", project.PathWithNamespace, "count", len(protectedBranches))

			approvalConfig, approvalRules, err := l.GatherApprovalConfig(ctx, project)
			if err != nil {
				l.Logger.Error("Error gathering approval config", "project", project.PathWithNamespace, "error", err)
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
			}
			if approvalConfig != nil {
				l.Logger.Debug("Gathered approval config", "project", project.PathWithNamespace,
					"approvals_before_merge", approvalConfig.ApprovalsBeforeMerge,
					"reset_on_push", approvalConfig.ResetApprovalsOnPush,
					"author_approval", approvalConfig.MergeRequestsAuthorApproval,
					"committer_approval_disabled", approvalConfig.MergeRequestsDisableCommittersApproval,
					"rules_count", len(approvalRules),
				)
			} else {
				l.Logger.Debug("Approval config not available", "project", project.PathWithNamespace)
			}

			pipelineRuns, err := l.GatherPipelineRuns(ctx, project)
			if err != nil {
				l.Logger.Error("Error gathering pipeline runs", "project", project.PathWithNamespace, "error", err)
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
			}
			l.Logger.Debug("Gathered pipeline runs", "project", project.PathWithNamespace, "count", len(pipelineRuns), "lookback_days", l.config.pipelineLookbackDays)

			lastPipeline, err := l.FetchLastPipelineRun(ctx, project)
			if err != nil {
				l.Logger.Error("Error fetching last pipeline run", "project", project.PathWithNamespace, "error", err)
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
			}
			if lastPipeline != nil {
				l.Logger.Debug("Fetched last pipeline run", "project", project.PathWithNamespace,
					"pipeline_id", lastPipeline.ID,
					"status", lastPipeline.Status,
					"ref", lastPipeline.Ref,
					"updated_at", lastPipeline.UpdatedAt,
				)
			} else {
				l.Logger.Debug("No pipeline runs found", "project", project.PathWithNamespace)
			}

			openMRs, err := l.GatherOpenMergeRequests(ctx, project)
			if err != nil {
				l.Logger.Error("Error gathering merge requests", "project", project.PathWithNamespace, "error", err)
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
			}
			l.Logger.Debug("Gathered open merge requests", "project", project.PathWithNamespace, "count", len(openMRs))

			lastRelease, err := l.FetchLatestRelease(ctx, project)
			if err != nil {
				l.Logger.Error("Error fetching latest release", "project", project.PathWithNamespace, "error", err)
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
			}
			if lastRelease != nil {
				l.Logger.Debug("Fetched latest release", "project", project.PathWithNamespace, "tag", lastRelease.TagName, "released_at", lastRelease.ReleasedAt)
			} else {
				l.Logger.Debug("No releases found", "project", project.PathWithNamespace)
			}

			codeOwners, err := l.FetchCodeOwners(ctx, project)
			if err != nil {
				l.Logger.Error("Error fetching CODEOWNERS", "project", project.PathWithNamespace, "error", err)
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
			}
			l.Logger.Debug("Fetched CODEOWNERS", "project", project.PathWithNamespace, "present", codeOwners != "")

			environments, err := l.GatherEnvironments(ctx, project)
			if err != nil {
				l.Logger.Error("Error gathering environments", "project", project.PathWithNamespace, "error", err)
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
			}
			l.Logger.Debug("Gathered environments", "project", project.PathWithNamespace, "count", len(environments))

			pushRules, err := l.GatherPushRules(ctx, project)
			if err != nil {
				// Push rules require GitLab Premium/Ultimate; treat as non-fatal
				l.Logger.Trace("Push rules not available (may require Premium tier)", "project", project.PathWithNamespace, "error", err)
			}
			if pushRules != nil {
				l.Logger.Debug("Gathered push rules", "project", project.PathWithNamespace,
					"prevent_secrets", pushRules.PreventSecrets,
					"reject_unsigned_commits", pushRules.RejectUnsignedCommits,
					"member_check", pushRules.MemberCheck,
					"commit_message_regex", pushRules.CommitMessageRegex != "",
				)
			} else {
				l.Logger.Debug("Push rules not available", "project", project.PathWithNamespace)
			}

			data := &SaturatedProject{
				Settings:          project,
				ProtectedBranches: protectedBranches,
				ApprovalConfig:    approvalConfig,
				ApprovalRules:     approvalRules,
				LastPipelineRun:   lastPipeline,
				PipelineRuns:      pipelineRuns,
				OpenMergeRequests: openMRs,
				LastRelease:       lastRelease,
				CodeOwners:        codeOwners,
				GroupMembers:      groupMembers,
				Environments:      environments,
				PushRules:         pushRules,
				HasCIConfig:       hasCIConfig(project, lastPipeline),
			}

			// Dump the full policy input before evaluation so operators can inspect the
			// exact JSON being sent to OPA when debugging policy behavior.
			if l.Logger.IsDebug() {
				if raw, err := json.MarshalIndent(data, "", "  "); err == nil {
					l.Logger.Debug("Policy input", "project", project.PathWithNamespace, "data", string(raw))
				} else {
					l.Logger.Debug("Policy input serialisation failed", "project", project.PathWithNamespace, "error", err)
				}
			}

			evidences, err := l.EvaluatePolicies(ctx, data, req)
			if err != nil {
				l.Logger.Error("Error evaluating policies", "project", project.PathWithNamespace, "error", err)
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
			}

			if err := apiHelper.CreateEvidence(ctx, evidences); err != nil {
				l.Logger.Error("Error creating evidence", "project", project.PathWithNamespace, "error", err)
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
			}
		}
	}

	return &proto.EvalResponse{Status: proto.ExecutionStatus_SUCCESS}, nil
}

// FetchProjects streams all non-archived projects in the configured group, respecting include/exclude filters.
func (l *GitLabReposPlugin) FetchProjects(ctx context.Context) (chan *gitlab.Project, chan error) {
	projectChan := make(chan *gitlab.Project)
	errChan := make(chan error)

	var included, excluded []string
	if l.config.IncludedRepositories != "" {
		included = strings.Split(l.config.IncludedRepositories, ",")
	}
	if l.config.ExcludedRepositories != "" {
		excluded = strings.Split(l.config.ExcludedRepositories, ",")
	}

	go func() {
		defer close(projectChan)
		defer close(errChan)

		opts := &gitlab.ListGroupProjectsOptions{
			ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1},
			Archived:    gitlab.Ptr(false),
		}

		for {
			projects, resp, err := l.client.Groups.ListGroupProjects(l.groupRef(), opts, gitlab.WithContext(ctx))
			if err != nil {
				errChan <- err
				return
			}

			for _, project := range projects {
				name := project.Name
				path := project.Path

				if len(included) > 0 && !slices.Contains(included, name) && !slices.Contains(included, path) {
					l.Logger.Trace("Skipping project (not included)", "project", name)
					continue
				}
				if len(excluded) > 0 && (slices.Contains(excluded, name) || slices.Contains(excluded, path)) {
					l.Logger.Trace("Skipping project (excluded)", "project", name)
					continue
				}

				projectChan <- project
			}

			if resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}
	}()

	return projectChan, errChan
}

// GatherProtectedBranches fetches all protected branches for a project, including push/merge access levels
// and whether code-owner approval is required.
func (l *GitLabReposPlugin) GatherProtectedBranches(ctx context.Context, project *gitlab.Project) ([]*gitlab.ProtectedBranch, error) {
	opts := &gitlab.ListProtectedBranchesOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1},
	}
	var all []*gitlab.ProtectedBranch
	for {
		branches, resp, err := l.client.ProtectedBranches.ListProtectedBranches(project.ID, opts, gitlab.WithContext(ctx))
		if err != nil {
			if isPermissionError(err) {
				l.Logger.Trace("No permission to fetch protected branches", "project", project.PathWithNamespace)
				return nil, nil
			}
			return nil, err
		}
		all = append(all, branches...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

// GatherApprovalConfig fetches the project-level MR approval configuration and named approval rules.
func (l *GitLabReposPlugin) GatherApprovalConfig(ctx context.Context, project *gitlab.Project) (*gitlab.ProjectApprovals, []*gitlab.ProjectApprovalRule, error) {
	approvals, _, err := l.client.Projects.GetApprovalConfiguration(project.ID, gitlab.WithContext(ctx))
	if err != nil {
		if isPermissionError(err) {
			l.Logger.Trace("No permission to fetch approval config", "project", project.PathWithNamespace)
			return nil, nil, nil
		}
		return nil, nil, err
	}

	rules, _, err := l.client.Projects.GetProjectApprovalRules(project.ID, &gitlab.GetProjectApprovalRulesListsOptions{}, gitlab.WithContext(ctx))
	if err != nil {
		if isPermissionError(err) {
			l.Logger.Trace("No permission to fetch approval rules", "project", project.PathWithNamespace)
			return approvals, nil, nil
		}
		return approvals, nil, err
	}

	return approvals, rules, nil
}

// GatherPipelineRuns fetches recent CI/CD pipeline executions within the configured lookback window.
func (l *GitLabReposPlugin) GatherPipelineRuns(ctx context.Context, project *gitlab.Project) ([]*gitlab.PipelineInfo, error) {
	cutoff := time.Now().AddDate(0, 0, -l.config.pipelineLookbackDays)
	opts := &gitlab.ListProjectPipelinesOptions{
		ListOptions:  gitlab.ListOptions{PerPage: 100, Page: 1},
		UpdatedAfter: &cutoff,
		OrderBy:      gitlab.Ptr("updated_at"),
		Sort:         gitlab.Ptr("desc"),
	}

	var all []*gitlab.PipelineInfo
	for {
		pipelines, resp, err := l.client.Pipelines.ListProjectPipelines(project.ID, opts, gitlab.WithContext(ctx))
		if err != nil {
			if isPermissionError(err) {
				l.Logger.Trace("No permission to fetch pipelines", "project", project.PathWithNamespace)
				return nil, nil
			}
			return nil, err
		}
		all = append(all, pipelines...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	l.Logger.Debug("Fetched pipeline runs", "project", project.PathWithNamespace, "count", len(all), "lookback_days", l.config.pipelineLookbackDays)
	return all, nil
}

// FetchLastPipelineRun returns the single most recent pipeline for the project, without any
// date filter. This gives policies a concrete timestamp to reason over regardless of how
// pipeline_lookback_days is configured.
func (l *GitLabReposPlugin) FetchLastPipelineRun(ctx context.Context, project *gitlab.Project) (*gitlab.PipelineInfo, error) {
	opts := &gitlab.ListProjectPipelinesOptions{
		ListOptions: gitlab.ListOptions{PerPage: 1, Page: 1},
		OrderBy:     gitlab.Ptr("updated_at"),
		Sort:        gitlab.Ptr("desc"),
	}
	pipelines, _, err := l.client.Pipelines.ListProjectPipelines(project.ID, opts, gitlab.WithContext(ctx))
	if err != nil {
		if isPermissionError(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(pipelines) == 0 {
		return nil, nil
	}
	return pipelines[0], nil
}

// GatherEnvironments fetches all deployment environments defined for the project.
func (l *GitLabReposPlugin) GatherEnvironments(ctx context.Context, project *gitlab.Project) ([]*gitlab.Environment, error) {
	opts := &gitlab.ListEnvironmentsOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1},
	}
	var all []*gitlab.Environment
	for {
		envs, resp, err := l.client.Environments.ListEnvironments(project.ID, opts, gitlab.WithContext(ctx))
		if err != nil {
			if isPermissionError(err) {
				l.Logger.Trace("No permission to fetch environments", "project", project.PathWithNamespace)
				return nil, nil
			}
			return nil, err
		}
		all = append(all, envs...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

// GatherPushRules fetches project-level push rules. Returns nil if the feature is unavailable (Free tier).
func (l *GitLabReposPlugin) GatherPushRules(ctx context.Context, project *gitlab.Project) (*gitlab.ProjectPushRules, error) {
	rules, _, err := l.client.Projects.GetProjectPushRules(project.ID, gitlab.WithContext(ctx))
	if err != nil {
		if isPermissionError(err) {
			return nil, nil
		}
		return nil, err
	}
	return rules, nil
}

// FetchLatestRelease returns the most recently published release for the project, or nil if none exist.
func (l *GitLabReposPlugin) FetchLatestRelease(ctx context.Context, project *gitlab.Project) (*gitlab.Release, error) {
	releases, _, err := l.client.Releases.ListReleases(project.ID, &gitlab.ListReleasesOptions{
		ListOptions: gitlab.ListOptions{PerPage: 1, Page: 1},
		OrderBy:     gitlab.Ptr("released_at"),
		Sort:        gitlab.Ptr("desc"),
	}, gitlab.WithContext(ctx))
	if err != nil {
		if isPermissionError(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(releases) == 0 {
		return nil, nil
	}
	return releases[0], nil
}

// hasCIConfig reports whether the project has ever had CI/CD configured.
// It uses the most recent pipeline (unrestricted by the lookback window) so this
// returns true even when all pipelines are outside the configured window.
func hasCIConfig(project *gitlab.Project, lastPipeline *gitlab.PipelineInfo) bool {
	if lastPipeline != nil {
		return true
	}
	return project.CIConfigPath != ""
}

func (l *GitLabReposPlugin) EvaluatePolicies(ctx context.Context, data *SaturatedProject, req *proto.EvalRequest) ([]*proto.Evidence, error) {
	var accumulatedErrors error

	activities := []*proto.Activity{
		{
			Title: "Collect GitLab Repository Data",
			Steps: []*proto.Step{
				{
					Title:       "Authenticate with GitLab",
					Description: "Authenticate with the GitLab API using a personal access token.",
				},
				{
					Title:       "Fetch Project Details",
					Description: "Retrieve detailed information about the GitLab project including protected branches, approval rules, pipelines, merge requests, and environments.",
				},
			},
		},
	}

	actors := []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework"),
				},
			},
			Props: nil,
		},
		{
			Title: "Continuous Compliance Framework - GitLab Repository Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-gitlab-repositories",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework's GitLab Repository Plugin"),
				},
			},
			Props: nil,
		},
	}

	components := []*proto.Component{
		{
			Identifier:  "common-components/gitlab-repository",
			Type:        "service",
			Title:       "GitLab Repository",
			Description: "A GitLab repository (project) is a discrete codebase or project workspace hosted within a GitLab group or namespace. It contains source code, documentation, configuration files, CI/CD pipelines, and version history managed through Git. Projects support access control, issues, merge requests, protected branches, and automated CI/CD pipelines.",
			Purpose:     "To serve as the authoritative and version-controlled location for a specific software project, enabling secure collaboration, code review, automation, and traceability of changes throughout the development lifecycle.",
		},
		{
			Identifier:  "common-components/version-control",
			Type:        "service",
			Title:       "Version Control",
			Description: "Version control systems track and manage changes to source code and configuration files over time. They provide collaboration, traceability, and the ability to audit or revert code to previous states.",
			Purpose:     "To maintain a complete and auditable history of code and configuration changes, enable collaboration across distributed teams, and support secure and traceable software development lifecycle (SDLC) practices.",
		},
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("gitlab-repository/%s", data.Settings.PathWithNamespace),
			Type:       "gitlab-repository",
			Title:      fmt.Sprintf("GitLab Repository [%s]", data.Settings.Name),
			Props: []*proto.Property{
				{
					Name:  "name",
					Value: data.Settings.Name,
				},
				{
					Name:  "path",
					Value: data.Settings.PathWithNamespace,
				},
				{
					Name:  "group",
					Value: l.config.Group,
				},
			},
			Links: []*proto.Link{
				{
					Href: data.Settings.WebURL,
					Text: policyManager.Pointer("Repository URL"),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{Identifier: "common-components/gitlab-repository"},
				{Identifier: "common-components/version-control"},
			},
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("gitlab-repository/%s", data.Settings.PathWithNamespace),
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("gitlab-group/%s", l.config.Group),
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/gitlab-repository",
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/version-control",
		},
	}

	evidences := make([]*proto.Evidence, 0)
	for _, policyPath := range req.GetPolicyPaths() {
		processor := policyManager.NewPolicyProcessor(
			l.Logger,
			map[string]string{
				"provider":   "gitlab",
				"type":       "repository",
				"repository": data.Settings.Path,
				"group":      l.config.Group,
			},
			subjects,
			components,
			inventory,
			actors,
			activities,
		)
		evidence, err := processor.GenerateResults(ctx, policyPath, data)
		evidences = slices.Concat(evidences, evidence)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, err)
		}
	}

	return evidences, accumulatedErrors
}

// isPermissionError returns true if the GitLab API error indicates a permissions or visibility issue.
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gitlab.ErrNotFound) {
		return true
	}
	var gitlabErr *gitlab.ErrorResponse
	if errors.As(err, &gitlabErr) {
		if gitlabErr.Response != nil {
			switch gitlabErr.Response.StatusCode {
			case 401, 403, 404:
				return true
			}
		}
	}
	return false
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	plugin := &GitLabReposPlugin{
		Logger: logger,
	}

	logger.Info("Starting GitLab Repositories Plugin")
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerV2GRPCPlugin{
				Impl: plugin,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
