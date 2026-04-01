package main

import (
	"context"

	gitlab "gitlab.com/gitlab-org/api/client-go"
	"golang.org/x/sync/errgroup"
)

const mergeRequestApprovalConcurrency = 4

// GatherOpenMergeRequests fetches all open merge requests for a project, enriched with
// per-MR approval state so policies can reason over approval rules and approvers.
// Approval state lookups are done with bounded concurrency to reduce latency on
// projects with many open merge requests without overwhelming the GitLab API.
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

	filtered := make([]*gitlab.BasicMergeRequest, 0, len(mrs))
	for _, mr := range mrs {
		if mr == nil {
			continue
		}
		filtered = append(filtered, mr)
	}

	result := make([]*OpenMergeRequest, len(filtered))
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(mergeRequestApprovalConcurrency)

	for i, mr := range filtered {
		i, mr := i, mr
		result[i] = &OpenMergeRequest{BasicMergeRequest: mr}

		group.Go(func() error {
			state, _, err := l.client.MergeRequestApprovals.GetApprovalState(project.ID, mr.IID, gitlab.WithContext(groupCtx))
			if err != nil {
				l.Logger.Warn("Could not fetch approval state for MR", "project", project.PathWithNamespace, "mr_iid", mr.IID, "error", err)
				return nil
			}

			result[i].ApprovalState = state
			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return nil, err
	}

	return result, nil
}
