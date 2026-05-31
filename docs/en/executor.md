<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         executor.md
Description:  Executor subsystem architecture including models, policy, and audit.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# Executor Subsystem

The executor gives the LLM Agent a **controlled and auditable** mechanism for
performing side effects beyond plain-text output. Every executable action is
declared through TOML, validated by the policy engine before execution, and
recorded in a SQLite audit log.

## Architecture

```text
ActionRequest
|
|-- Assign request_id
|
|-- CapabilityRegistry
|   |-- Load capabilities from configs/capabilities/*.toml
|   `-- Unknown capability -> reject -> AuditDB
|
|-- PolicyEngine
|   |-- Role and capability allowed_roles
|   |-- Parameter types, required fields, ranges, regex, choices
|   `-- Rate limits
|       `-- Rejected -> deny -> AuditDB
|
|-- API Key verification when user_db exists and request carries api_key
|   |-- verify_api_key()
|   `-- actor_id must match the API Key's owner
|       `-- Failure -> deny -> AuditDB
|
|-- PathGuard
|   |-- Checks only parameters declared as path_params
|   `-- Legacy fallback checks absolute path strings
|       `-- Out of bounds -> deny -> AuditDB
|
|-- dry_run?
|   |-- Yes -> AuditDB.record(DRY_RUN) -> return
|   `-- No
|
|-- HandlerRegistry
|   `-- handler(ActionRequest) -> ExecutionResult
|
`-- AuditDB
    `-- Record success / failed / rejected / denied result when audit_db_path is configured
```

## Configuration

Add an `[executor]` section to `suricata-llm-agent.toml`:

```toml
[executor]
enabled = true
capabilities_dir = "configs/capabilities"
audit_db_path = "auth-data/audit.db"
sandbox_root = ""         # Empty disables the global sandbox
dry_run = true            # Set false to enable real execution
disable_agent_mode = false
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Master switch for the executor subsystem |
| `capabilities_dir` | string | `"configs/capabilities"` | Directory containing `*.toml` capability declaration files |
| `audit_db_path` | string | `""` | SQLite audit database path. Empty disables persistent audit records |
| `sandbox_root` | string | `""` | Global filesystem sandbox root; all file operations must stay under this directory. Empty disables it |
| `dry_run` | bool | `true` | When true, handlers are not executed; requests are validated and recorded as `dry_run` |
| `disable_agent_mode` | bool | `false` | Force Pipeline mode even if the model supports tool calling |

## Declaring Capabilities

Each TOML file in `capabilities_dir` can declare one or more capabilities under
`[capability.<name>]` tables:

```toml
[capability.suricata_rule_suggest]
description = "Generate Suricata IDS rules from context"
handler     = "suricata_rule_suggest"
allowed_roles = ["Agent", "Owner"]
enabled     = true
requires_approval = false

[capability.suricata_rule_suggest.params.context]
type     = "string"
required = true

[capability.suricata_rule_suggest.params.severity]
type    = "integer"
min     = 1
max     = 4

[capability.suricata_rule_suggest.rate_limit]
max_calls      = 10
window_seconds = 60
```

### Parameter Constraints

| Field | Type | Description |
|-------|------|-------------|
| `type` | `string|integer|float|boolean` | Python type name used for validation |
| `required` | bool | Whether the parameter must be present |
| `pattern` | string (regex) | For `string` only; the value must fully match the regex |
| `min` | number | Minimum value for integer/float |
| `max` | number | Maximum value for integer/float |
| `choices` | list[string] | Allowed value list |

### Path Allowlist

Capabilities that involve file I/O must declare allowed directories:

```toml
[capability.file_op.paths.read]
dirs = ["/opt/suricata/rules"]

[capability.file_op.paths.write]
dirs = ["/opt/suricata/rules"]
```

`PathGuard` resolves symlinks before containment checks and verifies that paths
are inside both the capability's allowed directories and the global
`sandbox_root`.

Path declarations support variables expanded by the registry loader, such as
`{repo_dir}` and `{rules_path}`. Current Git and rule handlers use these
variables to restrict writes to `git.local_repo_path` and the rules directory.

### requires_approval

A capability can set `requires_approval = true`. In Agent mode, when the
Orchestrator sees such a capability, it does not execute it directly. It
downgrades the action to an approval notification, currently through a GitHub
issue for administrator review. `create_github_pr` requires approval by default.

## Policy Engine

Before any handler runs, `PolicyEngine` performs these checks in order:

1. **Enabled state**: the capability must not be disabled.
2. **Role check**: `actor_role` must appear in `allowed_roles`; an empty list
   means all roles are accepted.
3. **Identity check**: when the U-A-P database is available, `actor_id` must
   correspond to a real user, and the database role must match the request's
   `actor_role`.
4. **Parameter validation**: required parameters, undeclared parameters, type
   checks, regex matches, range checks, and choice allowlists.
5. **Rate limiting**: sliding-window counters keyed by `(capability, actor_id)`.

If the request carries an API Key, `ExecutorRuntime` verifies after policy
validation that the API Key is valid and belongs to the same `actor_id`. Failed
API Key verification prevents the request from reaching the handler.

Any failed check returns `PolicyDecision(allowed=False, reason=...)`. The
request is rejected and never reaches the handler.

## Audit Log

Every request is recorded in the configured audit database, regardless of
approval, rejection, dry-run, or failure. The template uses `auth-data/audit.db`;
an empty path disables persistence. The database is SQLite with WAL mode and
thread-safe access.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Autoincrement primary key |
| `request_id` | TEXT | UUID assigned to the request |
| `capability` | TEXT | Capability name |
| `actor_role` | TEXT | Requesting role, such as `Agent` |
| `actor_id` | TEXT | Actor identity string |
| `status` | TEXT | `success`, `rejected`, `failed`, or `dry_run` |
| `detail` | TEXT | Human-readable detail |
| `params_json` | TEXT | JSON-serialized parameters |
| `level` | TEXT | `info`, `warn`, `deny`, or `error` |
| `created_at` | TEXT | ISO-8601 UTC timestamp |

Audit logs can be queried through RMI:

```text
GET /executor/audit?limit=20
```

## RMI Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/executor/capabilities` | Any role | List all registered capability names |
| POST | `/executor/execute` | admin+ | Submit an execution request |
| GET | `/executor/audit` | admin+ | Query audit logs |

## Built-in Capabilities

| Capability | Handler | Description |
|------------|---------|-------------|
| `create_github_issue` | `create_github_issue` | Create an issue through the GitHub REST API |
| `create_github_pr` | `create_github_pr` | Create a pull request; defaults to `requires_approval = true` |
| `close_github_prs` | `close_github_prs` | Close old PRs from the fork default branch to upstream |
| `git_commit_and_push` | `git_commit_and_push` | Stage, commit, and push rule changes |
| `git_local_checkout_default` | `git_local_checkout_default` | Clean only the local worktree and switch back to the default branch; does not fetch or push |
| `git_repo_reset` | `git_repo_reset` | Scheduled Git workspace synchronization; force-pushes to the fork in fork mode |
| `git_clone_repo` | `git_clone_repo` | Clone the configured repository at startup |
| `suricata_rule_suggest` | `suricata_rule_suggest` | Validate and write Suricata rules |

### Execution Request Body

```json
{
  "capability": "suricata_rule_suggest",
  "params": {
    "context": "...",
    "severity": 2
  }
}
```

## Writing a Handler

Register a handler under `src/executor/handlers/`:

```python
from src.executor.handlers import register_handler
from src.executor.models import ActionRequest, ActionStatus, ExecutionResult

def my_handler(req: ActionRequest) -> ExecutionResult:
    # ... perform the operation ...
    return ExecutionResult(
        request_id=req.request_id,
        capability=req.capability,
        status=ActionStatus.SUCCESS,
        detail="completed",
        output={"result": "..."},
    )

register_handler("my_handler", my_handler)
```

## Security Notes

- **dry_run = true** is the default; set it to `false` only after capability
  declaration files have been validated.
- `PathGuard` resolves symlinks to block path traversal.
- Undeclared parameters are **strictly rejected**; no pass-through behavior is
  allowed.
- Rate limits are calculated independently by actor and capability; exhaustion
  is logged at `warn` level.
