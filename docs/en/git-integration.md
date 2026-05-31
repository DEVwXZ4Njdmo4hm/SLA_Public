<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         git-integration.md
Description:  Git and GitHub integration for automated issue and PR creation.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# Git and GitHub Integration

## Overview

Git integration lets the LLM Agent operate a local git repository, submit commits
upstream, and create GitHub Issues / Pull Requests through the GitHub REST API.
It primarily supports two workflows:

1. **Real-time alert -> Issue**: when real-time analysis detects a high-threat
   event, the system automatically creates a GitHub Issue to notify maintainers.
2. **Daily report -> rule generation -> PR**: after daily report analysis, the
   LLM decides whether new Suricata IDS rules are needed, validates them,
   commits them, and opens a PR.

All git/GitHub operations go through the Executor subsystem and are protected by
the U-A-P policy engine.

## Architecture

```text
Call sources
├── LogProcessor._maybe_create_issue()
│   └── Real-time high-threat event -> create_github_issue
├── DailyReportService._run_rule_generation()
│   └── Daily report high-threat communication pair -> rule generation -> commit / PR
└── main.py
    ├── _init_git_workspace() -> git_clone_repo
    └── _scheduled_git_reset() -> git_repo_reset

ActionRequest
|
`-- ExecutorRuntime
    ├── PolicyEngine (U-A-P): roles, parameters, API Key, rate limits
    ├── PathGuard: repository and rules-directory boundaries
    ├── AuditDB: records every attempt
    └── HandlerRegistry
        ├── create_github_issue ----------> GitHub REST API
        ├── create_github_pr -------------> GitHub REST API
        ├── close_github_prs -------------> GitHub REST API
        ├── git_clone_repo ---------------> local git CLI
        ├── git_commit_and_push ----------> local git CLI
        ├── git_repo_reset ---------------> local git CLI
        ├── git_local_checkout_default ---> local git CLI
        └── suricata_rule_suggest --------> rules_path/*.rules
```

## Configuration

### `suricata-llm-agent.toml` - `[git]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Whether git integration is enabled |
| `token` | string | `""` | GitHub Personal Access Token, stored in `credentials.db` |
| `remote_url` | string | `""` | Remote repository HTTPS URL |
| `default_branch` | string | `"main"` | Default branch name |
| `local_repo_path` | string | `"/app/git-workspace"` | Local clone path inside the container |
| `api_base_url` | string | `"https://api.github.com"` | GitHub API URL; change for GitHub Enterprise |
| `repo_owner` | string | `""` | Repository owner, organization or username |
| `repo_name` | string | `""` | Repository name |
| `auto_pr` | bool | `true` | Whether to create a PR automatically after daily-report rule generation |
| `auto_issue` | bool | `true` | Whether real-time analysis creates high-threat issues automatically |
| `issue_threat_threshold` | string | `"高"` | Minimum threat level that triggers automatic issues: `"高"` or `"严重"` |
| `rules_path` | string | `"rules/generated"` | Repository path where generated rules are stored |
| `validate_with_suricata` | bool | `false` | Whether to run medium validation with `suricata -T`; requires the Suricata binary in the container |
| `fork_owner` | string | `""` | GitHub username for Fork & PR mode. When set, the Agent clones and pushes to the fork, then opens a cross-repository PR. Empty means same-repository mode |

### `secrets.toml` - `[git]`

```toml
[git]
token = { value = "ghp_xxxx" }
```

### `deploy.toml` - `[git]`

```toml
[git]
# Git workspace is ephemeral — it lives only inside the container and is
# cloned fresh on each start.  No host bind-mount is needed.
```

The Git workspace is ephemeral and exists only inside the container. On each
container startup, `_init_git_workspace()` automatically runs `git clone`. This
avoids stale dirty state on the host and ensures every startup begins from the
latest remote repository state.

## Agent Identity Lifecycle

`LLMHandler` owns the runtime Agent identity. During instantiation:

1. It calls `bootstrap_agent(user_db)` to clean up Agent users left by the
   previous run and create a dedicated Agent user for this run.
2. It issues an independent API Key to that Agent user and records
   `key_record_id`.
3. Real-time analysis, daily-report rule generation, startup-time git clone, and
   scheduled reset reuse the same `agent_identity`; every `ActionRequest`
   carries this API Key and `actor_id`.

`LLMHandler.close()` calls `revoke_agent_session()` to delete that Agent user and
its API Key. `DailyReportService` only borrows the identity and does not create
or revoke API Keys on its own.

## Capability Declarations

Capability declarations live under `configs/capabilities/`:

- **`git.toml`**: seven capabilities:
  `create_github_issue`, `create_github_pr`, `close_github_prs`,
  `git_commit_and_push`, `git_local_checkout_default`, `git_repo_reset`,
  `git_clone_repo`
- **`suricata_rules.toml`**: `suricata_rule_suggest`

All capabilities allow `Agent`, `Administrator`, and `Owner` roles and configure
rate limits.

## Real-Time Analysis -> Automatic Issue

`LogProcessor._maybe_create_issue()` triggers when an LLM analysis result reaches
the threat threshold:

1. Check `config.GIT_ENABLED` and `config.GIT_AUTO_ISSUE`.
2. Compare `threat_level` with `issue_threat_threshold` using this order:
   harmless < low < medium < high < critical.
3. Deduplicate through `_IssueDedupCache` (LRU + TTL, max 200 entries, 1-hour
   expiration) to avoid repeated issues for the same event.
4. Build the issue title and body, then call `create_github_issue` through the
   executor.

### Issue Body Fields

| Field | Source | Description |
|-------|--------|-------------|
| **Threat level** | `parsed.threat_level` | LLM threat assessment |
| **Time** | `_source.@timestamp` | Event time |
| **Communication pair** | `src_hostname` / `src_ip` -> `dest_hostname` / `dest_ip` | Hostnames are preferred |
| **Event type** | `_source.event_type` | Suricata event type |
| **Event ID** | `_id` | ES document ID for tracing |
| **Index** | `_index` | ES index name for locating the data |
| **Alert rule** | `alert.signature` / `alert.signature_id` | Alert events only; includes rule name and SID |
| **Summary** | `parsed.summary` | LLM analysis summary |
| **Security hint** | `parsed.security_hint` | LLM security interpretation, if present |
| **Recommendation** | `parsed.recommendation` | LLM action recommendation, if present |

Issue title format: `[threat level] src_host -> dest_host (event_type)`. The
system automatically adds `auto-alert` and threat-level labels.

## Daily Report -> Rule Generation Pipeline

`DailyReportService._run_rule_generation_pipeline()` runs after the daily report
is generated:

1. Filter communication pairs whose threat level is high or critical.
2. Collect existing SIDs from the local repository for deduplication.
3. Call the LLM to generate Suricata rules in JSON format, using the prompt
   defined in `llm_prompt.toml [rule_generation]`.
4. Validate each rule through executor capability `suricata_rule_suggest`:
   - **Light validation**: regular-expression match for Suricata rule syntax.
   - **Medium validation** (optional): `suricata -T` syntax validation.
   - **Deduplication**: scan existing `.rules` files for SIDs.
5. Write validated rules into `rules_path`.
6. `git_commit_and_push` commits to an independent branch `ai-rules/{YYYYMMDD}`;
   in Fork mode it commits directly on the default branch. Before pushing, it
   removes remote refs that conflict with hierarchical branch names through
   `_delete_conflicting_remote_refs`.
7. If `auto_pr = true`, Fork mode first calls `close_github_prs` to close old
   PRs, then calls `create_github_pr` to create a cross-repository PR.
8. After completion, `git_local_checkout_default` cleans only the local worktree
   and switches back to the default branch. It does not fetch, pull, or push,
   avoiding disruption to the PR branch that was just created.

## Fork & PR Workflow

When `fork_owner` is non-empty, the Agent enters Fork mode:

1. **Clone**: `git_clone_repo` clones the fork repository
   (`fork_owner/repo_name`) and adds an `upstream` remote pointing to the
   original repository (`repo_owner/repo_name`).
2. **Commit & Push**: `git_commit_and_push` ignores the `branch` parameter,
   commits directly on the default branch, and pushes to the fork.
3. **PR**: `create_github_pr` automatically prefixes `head` with
   `fork_owner:` and creates a cross-repository pull request from fork to
   upstream.
4. **Close old PRs**: before creating a new PR, `close_github_prs` closes all
   open PRs from the fork default branch to upstream. The filter is
   `head = fork_owner:default_branch`, so only PRs created by the Agent's Fork
   mode are affected.
5. **Local cleanup**: after rule generation and PR creation,
   `git_local_checkout_default` only affects the local worktree inside the
   container.
6. **Scheduled Reset**: `git_repo_reset` fetches latest code from upstream,
   runs `reset --hard`, and force-pushes to the fork. This is triggered by the
   daily schedule and is not run immediately after PR creation.

This mode does not require write permission to the upstream repository. It
requires push permission to the fork and PR creation permission on the upstream
repository.

## Remote Ref Conflict Cleanup

Hierarchical branch names such as `ai-rules/20260326` conflict with an existing
remote branch named `ai-rules` because Git treats refs as paths. Cleanup has two
steps:

1. **Local cleanup** (`_delete_conflicting_refs()`): before creating the local
   branch, detect and delete conflicting local refs, including both prefix
   conflicts and child-path conflicts.
2. **Remote cleanup** (`_delete_conflicting_remote_refs()`): before push, run
   `git ls-remote --heads origin`, detect conflicting remote refs, and delete
   them so the push succeeds.

Both functions handle bidirectional conflicts: they delete existing branches that
are prefixes of the target branch, such as `ai-rules` blocking
`ai-rules/20260326`, and branches whose paths are under the target branch, such
as `ai-rules/20260325` blocking `ai-rules`.

## Scheduled Reset

The main loop includes a time check. Once per day, when the current time reaches
or passes the configured `reset_time`, it triggers `git_repo_reset`, discards all
local changes, and pulls the latest remote code. This mechanism is independent
of the daily report flow and prevents stale changes from accumulating even if no
daily report is generated.

In same-repository mode, `git_repo_reset` pulls the default branch, deletes local
non-default branches, and tries to delete corresponding remote branches. In Fork
mode, it synchronizes the default branch from upstream and force-pushes to the
fork, so it is not called immediately after PR creation.

Configure reset time in `[git].reset_time` as HH:MM:SS in 24-hour format:

```toml
[git]
reset_time = "02:00:00"   # Run reset once per day after 02:00:00 (default)
```

The program triggers reset **only** when the current day has not already run a
reset and the time is >= `reset_time`. It runs at most once per day.

## Container Dependencies

Container base image definitions under `configs/container_base/` include `git`
in `required_packages`. `COPY configs/capabilities/` in `Containerfile.in`
ensures capability declaration files are packaged into the image.

## Troubleshooting

### `cannot lock ref`

A hierarchical branch name such as `ai-rules/20260326` conflicts with an
existing ref named `ai-rules`. The system includes automatic cleanup through
`_delete_conflicting_refs` and `_delete_conflicting_remote_refs`, but if loose
ref files remain under `.git/refs/`, run:

```bash
git pack-refs --all
git remote prune origin
```

`git_repo_reset` automatically runs these commands on every reset.

### Fork Mode PR Creation Fails

1. Confirm that the `fork_owner` user has forked the `repo_owner/repo_name`
   repository.
2. Confirm that `GIT_TOKEN` has push permission to the fork and PR creation
   permission on the upstream repository.
3. Check the API response logged by `create_github_pr`. Common errors:
   - `422 Validation Failed`: head branch does not exist in the fork; check
     whether push succeeded.
   - `403 Forbidden`: insufficient token permissions.

### Duplicate Issues

`_IssueDedupCache` uses the first 120 characters of the summary as the
deduplication key and has a 1-hour TTL. If similar threats reappear at different
times, the system creates another issue after the TTL expires. This is expected:
persistent threats should continue to notify maintainers.

### Credential Management

`git.token` (GitHub Personal Access Token) is written to `credentials.db` from
`secrets.toml` during deployment and loaded automatically at runtime. It is
**not** stored in plaintext in `suricata-llm-agent.toml`. In non-container or
development environments, the `token` field can be set temporarily in the main
configuration for debugging only.

Similarly, `mail.client_id` and `mail.client_secret` have moved to the
`secrets.toml` -> `credentials.db` path. The main config keeps only commented
placeholders.

### fork_owner Configuration Constraint

`fork_owner` must be a valid GitHub username (letters, digits, hyphens; cannot
start or end with a hyphen), or an empty string to disable Fork mode. Schema
validation rejects invalid username formats.
