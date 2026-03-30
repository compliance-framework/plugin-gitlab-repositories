package main

import (
	"context"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// GatherGroupMembers fetches all members of the configured group, including inherited members
// from ancestor groups, so policies can reason over group access levels and membership.
func (l *GitLabReposPlugin) GatherGroupMembers(ctx context.Context) ([]*gitlab.GroupMember, error) {
	opts := &gitlab.ListGroupMembersOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1},
	}

	var members []*gitlab.GroupMember
	for {
		batch, resp, err := l.client.Groups.ListAllGroupMembers(l.groupRef(), opts, gitlab.WithContext(ctx))
		if err != nil {
			if isPermissionError(err) {
				l.Logger.Warn("Group members fetch unavailable; continuing without membership data", "group", l.config.Group, "error", err, "hint", "ensure group is configured as a numeric ID or full path and the token identity can view group members")
				return nil, nil
			}
			return nil, err
		}
		members = append(members, batch...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	l.Logger.Debug("Fetched group members", "group", l.config.Group, "count", len(members))
	return members, nil
}
