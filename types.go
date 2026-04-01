package main

import (
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// OpenMergeRequest represents a merge request alongside its per-MR approval state,
// so policy evaluation can reason over approvers and approval rules without extra joins.
type OpenMergeRequest struct {
	*gitlab.BasicMergeRequest
	ApprovalState *gitlab.MergeRequestApprovalState `json:"approval_state"`
}

// SaturatedProject holds all collected data for a single GitLab project.
type SaturatedProject struct {
	// Settings contains the full project metadata (visibility, default branch, etc.)
	Settings *gitlab.Project `json:"settings"`

	// ProtectedBranches lists all protected branches and their push/merge access levels.
	ProtectedBranches []*gitlab.ProtectedBranch `json:"protected_branches"`

	// ApprovalConfig holds the project-level MR approval settings
	// (e.g. approvals_before_merge, reset_approvals_on_push, author approval rules).
	ApprovalConfig *gitlab.ProjectApprovals `json:"approval_config"`

	// ApprovalRules lists the project-level approval rules (named rule sets, eligible approvers).
	ApprovalRules []*gitlab.ProjectApprovalRule `json:"approval_rules"`

	// LastPipelineRun is the single most recent pipeline for the project regardless of date,
	// or nil if the project has never had a pipeline. Policies use this to compute how long
	// ago CI last ran (e.g. created_at / updated_at older than 90 days) independently of
	// the lookback window applied to PipelineRuns.
	LastPipelineRun *gitlab.PipelineInfo `json:"last_pipeline_run"`

	// PipelineRuns holds recent CI/CD pipeline executions within the configured lookback window.
	// Use this for failure-rate analysis. An empty slice means no pipeline ran within the window.
	PipelineRuns []*gitlab.PipelineInfo `json:"pipeline_runs"`

	// OpenMergeRequests lists open MRs enriched with their per-MR approval state.
	OpenMergeRequests []*OpenMergeRequest `json:"merge_requests"`

	// LastRelease is the most recently published release, or nil if none exist.
	LastRelease *gitlab.Release `json:"last_release"`

	// CodeOwners is the decoded content of the CODEOWNERS file, or empty string if absent.
	CodeOwners string `json:"code_owners"`

	// GroupMembers is the full membership list of the parent group (including inherited members).
	GroupMembers []*gitlab.GroupMember `json:"group_members"`

	// Environments lists all deployment environments defined for the project.
	Environments []*gitlab.Environment `json:"environments"`

	// PushRules holds project-level push rules (GitLab Premium/Ultimate only; nil on free tier).
	PushRules *gitlab.ProjectPushRules `json:"push_rules"`

	// HasCIConfig indicates whether CI/CD is configured for the project.
	HasCIConfig bool `json:"has_ci_config"`
}
