# Compliance Framework - GitLab Repository Plugin

Fetches information regarding GitLab repositories, including

- Repository metadata and settings
- Merge request and approval configuration
- Pipeline history and recent runs

This plugin is intended to be run as part of an aggregate agent, and will execute the policy suite for each repository.

## Authentication

To authenticate this plugin, you must provide a token which has at minimum the following permissions:

- `read_api` (recommended) or `api` - Required to read groups, projects, merge requests, pipelines, releases, and other repository metadata.
- `read_user` alone is not sufficient for this plugin. It only covers user/profile endpoints and does not grant access to group or project APIs.

The token identity must also be able to view the configured group. For private groups, this means the backing user or service account must be a member of that group with enough visibility to read the resources the plugin queries.

## Configuration

```yaml
plugins:
  gitlab_repos:
    token: "glpat-abc123"
    # Numeric GitLab group ID or full group path. Use "parent/subgroup" for subgroups.
    group: platform/security
    # The following items are mutually exclusive, so cannot be set together. If neither are set, all repos are
    # pulled and tested, otherwise the selection is chosen below
    included_repositories: foo,bar,baz
    excluded_repositories: quix,quiz
```

If `group` is configured as a short name instead of a numeric ID or full path, GitLab can return `404 Not Found` for group-scoped endpoints. The plugin now validates the configured group up front and fails with a specific error in that case.

If group-member enumeration is inaccessible after group resolution succeeds, the plugin logs a warning and continues evaluating repositories without `group_members` data.

## Integration testing

This plugin contains unit tests as well as integration tests.

The integration tests need a GitLab token to call the GitLab API.

```shell
GITLAB_TOKEN="<TOKEN>" go test ./... -v --tags integration
```

## Policies

When writing OPA/Rego policies for this plugin, they must be added under the `compliance_framework` Rego package:

```rego
# deny_critical_severity.rego
# package compliance_framework.[YOUR_RULE_PATH]
package compliance_framework.deny_critical_severity
```

## Releases

This plugin is released using GoReleaser to build binaries, and GOOCI to upload artifacts to OCI,
which will ensure a binary is built for most OS and Architecture combinations.

You can find the binaries on each release of this plugin in the GitHub Releases page.

You can find the OCI implementations in the GitHub Packages page.
