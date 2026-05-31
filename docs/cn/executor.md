<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         executor.md
Description:  Executor subsystem architecture including models, policy, and audit.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# 执行器子系统

执行器为 LLM Agent 提供了一个**受控的、可审计的**执行机制，使其能够在纯文本输出之外执行副作用操作。所有可执行动作均通过 TOML 文件声明，经策略引擎校验后方可执行，且每次执行均记录到 SQLite 审计日志中。

## 架构

```
ActionRequest
│
├── 分配 request_id
│
├── CapabilityRegistry
│   ├── 从 configs/capabilities/*.toml 加载能力
│   └── 未知 capability → reject → AuditDB
│
├── PolicyEngine
│   ├── 角色与 capability allowed_roles
│   ├── 参数类型、必填项、范围、正则、choices
│   └── 速率限制
│       └── 拒绝 → deny → AuditDB
│
├── API Key 校验（存在 user_db 且请求携带 api_key 时）
│   ├── verify_api_key()
│   └── actor_id 必须与 API Key 所属用户一致
│       └── 失败 → deny → AuditDB
│
├── PathGuard
│   ├── 仅检查声明为 path_params 的参数
│   └── legacy fallback 检查绝对路径字符串
│       └── 越界 → deny → AuditDB
│
├── dry_run?
│   ├── 是 → AuditDB.record(DRY_RUN) → 返回
│   └── 否
│
├── HandlerRegistry
│   └── handler(ActionRequest) → ExecutionResult
│
└── AuditDB
    └── 记录 success / failed / rejected / denied 结果（配置 audit_db_path 时）
```

## 配置

在 `suricata-llm-agent.toml` 中添加 `[executor]` 节：

```toml
[executor]
enabled = true
capabilities_dir = "configs/capabilities"
audit_db_path = "auth-data/audit.db"
sandbox_root = ""         # 为空则不启用全局沙箱
dry_run = true            # 设为 false 以启用实际执行
disable_agent_mode = false
```

| 键                 | 类型   | 默认值                   | 说明 |
|--------------------|--------|--------------------------|------|
| `enabled`          | bool   | `false`                  | 执行器子系统总开关。 |
| `capabilities_dir` | string | `"configs/capabilities"` | 存放 `*.toml` 能力声明文件的目录。 |
| `audit_db_path`    | string | `""`                     | SQLite 审计数据库路径。为空则不持久化审计记录。 |
| `sandbox_root`     | string | `""`                     | 全局文件系统沙箱根目录，所有文件操作必须在此目录内。为空则不启用。 |
| `dry_run`          | bool   | `true`                   | 为 true 时不执行任何 handler，仅校验并以 `dry_run` 状态记录日志。 |
| `disable_agent_mode` | bool | `false` | 强制禁用 Agent 模式，即使模型支持 tool calling 也使用 Pipeline 模式。 |

## 声明能力

`capabilities_dir` 中的每个 TOML 文件可在 `[capability.<name>]` 表下声明一个或多个能力：

```toml
[capability.suricata_rule_suggest]
description = "根据上下文生成 Suricata IDS 规则"
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

### 参数约束

| 字段       | 类型              | 说明 |
|------------|-------------------|------|
| `type`     | `string\|integer\|float\|boolean` | 用于校验的 Python 类型名。 |
| `required` | bool              | 该参数是否必须提供。 |
| `pattern`  | string（正则）    | 仅适用于 `string` 类型，值必须完全匹配该正则。 |
| `min`      | number            | 最小值（integer/float）。 |
| `max`      | number            | 最大值（integer/float）。 |
| `choices`  | list[string]      | 可接受的值白名单。 |

### 路径白名单

若某能力涉及文件 I/O，须声明允许访问的目录：

```toml
[capability.file_op.paths.read]
dirs = ["/opt/suricata/rules"]

[capability.file_op.paths.write]
dirs = ["/opt/suricata/rules"]
```

`PathGuard` 在进行包含性检查之前会解析所有符号链接，同时验证路径是否在能力声明的允许目录**以及**全局 `sandbox_root` 之内。

路径声明支持由注册表加载时展开的变量，例如 `{repo_dir}` 和 `{rules_path}`。当前 Git / 规则 handler 使用这些变量把写入范围限制在 `git.local_repo_path` 和规则目录下。

### requires_approval

能力可声明 `requires_approval = true`。Agent 模式下，Orchestrator 遇到这类能力时不会直接执行，而是降级为审批通知（当前通过 GitHub issue 通知管理员）。例如 `create_github_pr` 默认要求审批。

## 策略引擎

在 handler 执行之前，`PolicyEngine` 按顺序执行以下检查：

1. **启用状态** — 该能力不得处于禁用状态。
2. **角色校验** — `actor_role` 必须出现在 `allowed_roles` 中（空列表表示任意角色均可）。
3. **身份校验** — 当 U-A-P 数据库可用时，`actor_id` 必须对应真实用户，且数据库中的角色必须与请求中的 `actor_role` 一致。
4. **参数验证** — 必需参数是否存在、是否有未声明参数、类型检查、正则匹配、范围检查以及选项白名单。
5. **速率限制** — 按 `(capability, actor_id)` 为键的滑动窗口计数器。

如果请求携带 API Key，`ExecutorRuntime` 会在策略校验后继续验证该 API Key 有效且归属于同一个 `actor_id`，验证失败的请求不会到达 handler。

任一检查失败将返回 `PolicyDecision(allowed=False, reason=...)`，请求被拒绝，不会到达 handler。

## 审计日志

每一个请求——无论批准、拒绝、dry-run 还是失败——均被记录到配置的审计数据库（配置模板使用 `auth-data/audit.db`；为空则不持久化，SQLite，WAL 模式，线程安全）：

| 列           | 类型    | 说明 |
|--------------|---------|------|
| `id`         | INTEGER | 自增主键。 |
| `request_id` | TEXT    | 请求时分配的 UUID。 |
| `capability` | TEXT    | 能力名称。 |
| `actor_role` | TEXT    | 请求者角色（如 `Agent`）。 |
| `actor_id`   | TEXT    | 身份标识字符串。 |
| `status`     | TEXT    | `success`、`rejected`、`failed`、`dry_run`。 |
| `detail`     | TEXT    | 可读的说明信息。 |
| `params_json`| TEXT    | 参数的 JSON 序列化。 |
| `level`      | TEXT    | `info`、`warn`、`deny`、`error`。 |
| `created_at` | TEXT    | ISO-8601 时间戳（UTC）。 |

可通过 RMI 端点查询审计日志：

```
GET /executor/audit?limit=20
```

## RMI 端点

| 方法   | 路径                      | 权限要求 | 说明 |
|--------|---------------------------|----------|------|
| GET    | `/executor/capabilities`  | 任意角色 | 列出所有已注册的能力名称。 |
| POST   | `/executor/execute`       | admin+   | 提交执行请求。 |
| GET    | `/executor/audit`         | admin+   | 查询审计日志。 |

## 内置能力

| 能力 | Handler | 说明 |
|------|---------|------|
| `create_github_issue` | `create_github_issue` | 通过 GitHub REST API 创建 Issue |
| `create_github_pr` | `create_github_pr` | 创建 Pull Request，默认 `requires_approval = true` |
| `close_github_prs` | `close_github_prs` | 关闭 fork 默认分支到上游的旧 PR |
| `git_commit_and_push` | `git_commit_and_push` | 暂存、提交并推送规则变更 |
| `git_local_checkout_default` | `git_local_checkout_default` | 仅清理本地工作树并切回默认分支，不 fetch、不 push |
| `git_repo_reset` | `git_repo_reset` | 定时同步 Git 工作区；fork 模式下会 force-push 到 fork |
| `git_clone_repo` | `git_clone_repo` | 启动时克隆配置的仓库 |
| `suricata_rule_suggest` | `suricata_rule_suggest` | 验证并写入 Suricata 规则 |

### 执行请求体

```json
{
  "capability": "suricata_rule_suggest",
  "params": {
    "context": "...",
    "severity": 2
  }
}
```

## 编写 Handler

在 `src/executor/handlers/` 中注册 handler：

```python
from src.executor.handlers import register_handler
from src.executor.models import ActionRequest, ActionStatus, ExecutionResult

def my_handler(req: ActionRequest) -> ExecutionResult:
    # ... 执行操作 ...
    return ExecutionResult(
        request_id=req.request_id,
        capability=req.capability,
        status=ActionStatus.SUCCESS,
        detail="完成",
        output={"result": "..."},
    )

register_handler("my_handler", my_handler)
```

## 安全说明

- **dry_run = true** 是默认值——仅在验证能力声明文件无误后才应设为 `false`。
- `PathGuard` 通过解析符号链接来阻止路径遍历攻击。
- 未声明的参数会被**严格拒绝**，不存在透传行为。
- 速率限制按 actor、按能力独立计算；耗尽时以 `warn` 级别记录日志。
