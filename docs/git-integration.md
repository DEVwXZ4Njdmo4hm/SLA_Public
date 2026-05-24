<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         git-integration.md
Description:  Git and GitHub integration for automated issue and PR creation.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# Git 与 GitHub 集成

## 概述

Git 集成使 LLM Agent 具备操作本地 git 仓库、向上游提交 commit 并通过 GitHub REST API 创建 Issue / Pull Request 的能力。该功能主要服务于两个场景：

1. **实时告警 → Issue**：实时分析中发现高威胁事件时自动创建 GitHub Issue，通知维护者。
2. **日报 → 规则生成 → PR**：日报分析完成后，LLM 判断是否需要生成新的 Suricata IDS 规则，通过验证后 commit 并提交 PR。

所有 git/GitHub 操作均通过执行器（Executor）子系统完成，受 U-A-P 策略引擎保护。

## 架构

```
调用来源
├── LogProcessor._maybe_create_issue()
│   └── 实时高威胁事件 → create_github_issue
├── DailyReportService._run_rule_generation()
│   └── 日报高威胁通信对 → 规则生成 → commit / PR
└── main.py
    ├── _init_git_workspace() → git_clone_repo
    └── _scheduled_git_reset() → git_repo_reset

ActionRequest
│
└── ExecutorRuntime
    ├── PolicyEngine (U-A-P)：角色、参数、API Key、速率限制
    ├── PathGuard：仓库与规则目录边界
    ├── AuditDB：记录每次尝试
    └── HandlerRegistry
        ├── create_github_issue ───────────▶ GitHub REST API
        ├── create_github_pr ──────────────▶ GitHub REST API
        ├── close_github_prs ──────────────▶ GitHub REST API
        ├── git_clone_repo ────────────────▶ 本地 git CLI
        ├── git_commit_and_push ───────────▶ 本地 git CLI
        ├── git_repo_reset ────────────────▶ 本地 git CLI
        ├── git_local_checkout_default ────▶ 本地 git CLI
        └── suricata_rule_suggest ─────────▶ rules_path/*.rules
```

## 配置

### `suricata-llm-agent.toml` — `[git]` 节

| 键 | 类型 | 默认值 | 说明 |
|---|------|-------|------|
| `enabled` | bool | `false` | 是否启用 git 集成 |
| `token` | string | `""` | GitHub Personal Access Token（存储在 `credentials.db` 中） |
| `remote_url` | string | `""` | 远程仓库 HTTPS 地址 |
| `default_branch` | string | `"main"` | 默认分支名 |
| `local_repo_path` | string | `"/app/git-workspace"` | 容器内本地克隆路径 |
| `api_base_url` | string | `"https://api.github.com"` | GitHub API 地址（GitHub Enterprise 需修改） |
| `repo_owner` | string | `""` | 仓库所有者（组织名或用户名） |
| `repo_name` | string | `""` | 仓库名 |
| `auto_pr` | bool | `true` | 日报规则生成后是否自动创建 PR |
| `auto_issue` | bool | `true` | 实时分析是否自动创建高威胁 Issue |
| `issue_threat_threshold` | string | `"高"` | 触发自动 Issue 的最低威胁等级（`"高"` 或 `"严重"`） |
| `rules_path` | string | `"rules/generated"` | 仓库内生成规则的存放路径 |
| `validate_with_suricata` | bool | `false` | 是否使用 `suricata -T` 进行中量验证（需容器内有 suricata 二进制） |
| `fork_owner` | string | `""` | 启用 Fork & PR 模式的 GitHub 用户名。设置后，Agent 克隆并推送到 fork，向上游创建跨仓库 PR。留空为同仓库模式 |

### `secrets.toml` — `[git]` 节

```toml
[git]
token = { value = "ghp_xxxx" }
```

### `deploy.toml` — `[git]` 节

```toml
[git]
# Git workspace is ephemeral — it lives only inside the container and is
# cloned fresh on each start.  No host bind-mount is needed.
```

Git 工作区是临时性的，仅存在于容器内部。每次容器启动时，`_init_git_workspace()` 会自动执行 `git clone`。这避免了宿主机上残留的脏状态，并确保每次启动都基于最新的远程仓库。

## Agent 身份生命周期

`LLMHandler` 是运行期 Agent 身份的所有者。实例化时：

1. 调用 `bootstrap_agent(user_db)` 清理上次运行遗留的 Agent 用户，并创建本次运行专属的 Agent 用户。
2. 为该 Agent 用户发放一个独立的 API Key，记录 `key_record_id`。
3. 后续实时分析、日报规则生成、启动时 git clone 和定时 reset 复用同一个 `agent_identity`，所有 `ActionRequest` 均携带该 API Key 和 `actor_id`。

`LLMHandler.close()` 调用 `revoke_agent_session()` 删除该 Agent 用户及其 API Key。`DailyReportService` 只借用该身份，不单独创建或撤销 API Key。

## 能力声明

能力声明位于 `configs/capabilities/`：

- **`git.toml`** — 7 个 capability：`create_github_issue`、`create_github_pr`、`close_github_prs`、`git_commit_and_push`、`git_local_checkout_default`、`git_repo_reset`、`git_clone_repo`
- **`suricata_rules.toml`** — `suricata_rule_suggest`

所有 capability 均允许 `Agent`、`Administrator`、`Owner` 角色调用，并配置了速率限制。

## 实时分析 → 自动 Issue

`LogProcessor._maybe_create_issue()` 在每条日志的 LLM 分析结果达到威胁阈值时触发：

1. 检查 `config.GIT_ENABLED` 和 `config.GIT_AUTO_ISSUE`。
2. 将 `threat_level` 与 `issue_threat_threshold` 比较（等级序：无危 < 低 < 中 < 高 < 严重）。
3. 通过 `_IssueDedupCache`（LRU + TTL，最大 200 条，1 小时过期）去重，防止对同一事件重复创建 Issue。
4. 构造 Issue 标题和正文，通过执行器调用 `create_github_issue`。

### Issue 正文字段

| 字段 | 来源 | 说明 |
|------|------|------|
| **威胁等级** | `parsed.threat_level` | LLM 评估的威胁等级 |
| **时间** | `_source.@timestamp` | 事件发生时间 |
| **通信对** | `src_hostname` / `src_ip` → `dest_hostname` / `dest_ip` | 优先使用主机名 |
| **事件类型** | `_source.event_type` | Suricata 事件类型 |
| **事件 ID** | `_id` | ES 文档 ID，用于溯源 |
| **索引** | `_index` | ES 索引名，用于定位数据 |
| **告警规则** | `alert.signature` / `alert.signature_id` | 仅 alert 类型事件，含规则名称和 SID |
| **摘要** | `parsed.summary` | LLM 分析摘要 |
| **安全提示** | `parsed.security_hint` | LLM 安全建议（如有） |
| **建议措施** | `parsed.recommendation` | LLM 行动建议（如有） |

Issue 标题格式：`[威胁等级] src_host → dest_host (event_type)`，自动添加 `auto-alert` 和威胁等级标签。

## 日报 → 规则生成管线

`DailyReportService._run_rule_generation_pipeline()` 在日报生成完毕后执行：

1. 筛选威胁等级为「高」或「严重」的通信对。
2. 收集本地仓库已有的 SID 列表（去重用）。
3. 调用 LLM 生成 Suricata 规则（JSON 格式，prompt 定义在 `llm_prompt.toml [rule_generation]`）。
4. 逐条通过执行器的 `suricata_rule_suggest` 验证：
   - **轻量验证**：正则匹配 Suricata 规则语法结构。
   - **中量验证**（可选）：`suricata -T` 语法校验。
   - **去重**：扫描已有 `.rules` 文件的 SID。
5. 验证通过的规则写入 `rules_path`。
6. `git_commit_and_push` 提交到独立分支 `ai-rules/{YYYYMMDD}`（Fork 模式下直接在默认分支提交）。推送前自动清理与层级分支名冲突的远程 ref（`_delete_conflicting_remote_refs`）。
7. 若 `auto_pr = true`，Fork 模式下先调用 `close_github_prs` 关闭旧 PR，再通过 `create_github_pr` 创建跨仓库 PR。
8. 完成后调用 `git_local_checkout_default` 仅清理本地工作树并切回默认分支，不执行 fetch、pull 或 push，避免破坏刚创建的 PR 分支。

## Fork & PR 工作流

当 `fork_owner` 配置为非空值时，Agent 进入 Fork 模式：

1. **Clone**：`git_clone_repo` 克隆 fork 仓库（`fork_owner/repo_name`），并自动添加 `upstream` remote 指向原始仓库（`repo_owner/repo_name`）。
2. **Commit & Push**：`git_commit_and_push` 忽略 `branch` 参数，直接在默认分支（如 `main`）上提交并推送到 fork。
3. **PR**：`create_github_pr` 自动在 `head` 参数前加 `fork_owner:` 前缀，创建从 fork 到上游仓库的跨仓库 Pull Request。
4. **关闭旧 PR**：`close_github_prs` 在创建新 PR 前，自动关闭所有从 fork 默认分支到上游的已有 open PR，避免 PR 堆积。过滤条件为 `head = fork_owner:default_branch`，因此仅影响 Agent 通过 Fork 模式创建的 PR，不会误关来自其他分支的 PR。
5. **本地清理**：规则生成和 PR 创建完成后调用 `git_local_checkout_default`，只影响容器内本地工作树。
6. **定时 Reset**：`git_repo_reset` 从 `upstream` fetch 最新代码，`reset --hard` 后 `push --force` 到 fork，使 fork 与上游完全同步；该动作由每日定时任务触发，不在 PR 创建后立即执行。

该模式无需上游仓库的写权限，仅需 fork 仓库的推送权限和上游仓库的 PR 创建权限。

## 远程 Ref 冲突清理

使用层级分支名（如 `ai-rules/20260326`）时，若远程已存在名为 `ai-rules` 的分支，Git 会因 ref 路径冲突（文件 vs 目录）而拒绝推送。清理分两步：

1. **本地清理**（`_delete_conflicting_refs()`）：在创建本地分支前，检测并删除冲突的本地 ref（包括前缀冲突和子路径冲突两种情况）。
2. **远程清理**（`_delete_conflicting_remote_refs()`）：在推送前通过 `git ls-remote --heads origin` 检测并删除冲突的远程 ref，确保推送成功。

两个函数均处理双向冲突：既删除作为目标分支前缀的已有分支（如 `ai-rules` 阻塞 `ai-rules/20260326`），也删除以目标分支为前缀的子分支（如 `ai-rules/20260325` 阻塞 `ai-rules`）。

## 定时 Reset

主循环中内置时间检查：每日到达配置的 `reset_time` 时刻后自动触发一次 `git_repo_reset`，丢弃所有本地更改并拉取远程最新代码。该机制独立于日报流程，确保即使日报未生成，本地仓库也不会积累陈旧的更改。

在 same-repo 模式下，`git_repo_reset` 会拉取默认分支、删除本地非默认分支，并尽量删除对应远程分支。在 Fork 模式下，它会从 upstream 同步默认分支并 force-push 到 fork，因此不会在创建 PR 后立即调用。

重置时间通过 `[git]` 配置节的 `reset_time`（HH:MM:SS，24 小时制）控制：

```toml
[git]
reset_time = "02:00:00"   # 每日 02:00:00 之后执行 reset（默认值）
```

程序**仅**在当日时间 ≥ `reset_time` 且尚未执行过当日 reset 时触发，每日最多执行一次。

## 容器依赖

容器基础镜像（`configs/container_base/`）的 `required_packages` 已包含 `git`。`Containerfile.in` 中 `COPY configs/capabilities/` 确保能力声明文件被打包到镜像中。

## 故障排查

### `cannot lock ref` 错误

层级分支名（`ai-rules/20260326`）与已有的同名 ref（`ai-rules`）冲突。系统已内置自动清理（`_delete_conflicting_refs` + `_delete_conflicting_remote_refs`），但如果 `.git/refs/` 中残留松散 ref 文件，可手动执行：

```bash
git pack-refs --all
git remote prune origin
```

`git_repo_reset` 在每次重置时会自动执行这两个命令。

### Fork 模式 PR 创建失败

1. 确认 `fork_owner` 指定的用户已 fork 了 `repo_owner/repo_name` 仓库。
2. 确认 `GIT_TOKEN` 拥有 fork 仓库的 push 权限和上游仓库的 PR 创建权限。
3. 检查日志中 `create_github_pr` 的 API 响应，常见错误：
   - `422 Validation Failed`：head 分支不存在于 fork，检查推送是否成功。
   - `403 Forbidden`：Token 权限不足。

### Issue 重复创建

`_IssueDedupCache` 使用摘要前 120 字符作为去重键，TTL 为 1 小时。如果同类威胁在不同时段重复出现，系统会在 TTL 过期后再次创建 Issue。这是预期行为——持续出现的威胁应当被反复通知。

### 凭据管理

`git.token`（GitHub Personal Access Token）通过 `secrets.toml` 在部署阶段写入 `credentials.db`，运行时由主配置自动从数据库加载，**不以明文存储在 `suricata-llm-agent.toml` 中**。如需在非容器/开发环境下跳过 `credentials.db`，可在主配置文件中临时设置 `token` 字段（仅限调试用途）。

同理，`mail.client_id` 和 `mail.client_secret` 也已迁移至 `secrets.toml` → `credentials.db` 链路，主配置中仅保留注释占位。

### fork_owner 配置约束

`fork_owner` 的值必须是合法的 GitHub 用户名（字母、数字、连字符，不能以连字符开头或结尾），或者设为空字符串以禁用 Fork 模式。Schema 校验会拒绝不合法的用户名格式。
