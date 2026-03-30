package main

import (
	"context"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// GatherOpenMergeRequests fetches all open merge requests for a project, enriched with
// per-MR approval state so policies can reason over approval rules and approvers.
func (l *GitLabReposPlugin) GatherOpenMergeRequests(ctx context.Context, project *gitlab.Project) ([]*OpenMergeRequest, error) {
	opts := &gitlab.ListProjectMergeRequestsOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1},
		State:       gitlab.Ptr("opened"),
	}

	var mrs []*gitlab.BasicMergeRequest
	for {
		batch, resp, err := l.client.MergeRequests.ListProjectMergeRequests(project.ID, opts, gitlab.WithContext(ctx))
		if err != nil {
			if isPermissionError(err) {
				l.Logger.Trace("No permission to fetch merge requests", "project", project.PathWithNamespace)
				return nil, nil
			}
			return nil, err
		}
		mrs = append(mrs, batch...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	result := make([]*OpenMergeRequest, 0, len(mrs))
	for _, mr := range mrs {
		if mr == nil {
			continue
		}

		state, _, err := l.client.MergeRequestApprovals.GetApprovalState(project.ID, mr.IID, gitlab.WithContext(ctx))
		if err != nil {
			l.Logger.Warn("Could not fetch approval state for MR", "project", project.PathWithNamespace, "mr_iid", mr.IID, "error", err)
			result = append(result, &OpenMergeRequest{BasicMergeRequest: mr})
			continue
		}

		result = append(result, &OpenMergeRequest{
			BasicMergeRequest: mr,
			ApprovalState:     state,
		})
	}

	return result, nil
}
