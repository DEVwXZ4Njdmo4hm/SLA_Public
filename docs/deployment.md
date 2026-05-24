<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         deployment.md
Description:  Deployment guide covering prerequisites, workflow, and configuration steps.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# 部署指南

## 概述

部署系统（`deploy.py`）是一个交互式容器化部署工具，从 TOML 配置和模板文件生成 Containerfile 与 Quadlet 服务文件，完成构建上下文准备、凭据数据库生成、镜像构建和 systemd 服务安装。

整个流程包括：**配置预检 → 获取 sudo → 准备构建上下文 → 生成/更新 credentials.db → OAuth2 令牌配置 → 模板渲染 → 镜像构建 → Quadlet 安装与服务重启**。

## 前置条件

- `podman`（容器运行时）
- `sudo`（权限提升）
- `systemctl`（systemd 服务管理）
- 交互式终端（部署脚本会检查 TTY，拒绝非交互环境运行）

## 运行

```bash
python deploy.py
```

脚本会以交互方式引导完成整个部署流程，包括 sudo 密码输入和（可选的）OAuth2 授权。

## 部署流程

```
Step 0: 检查运行环境
  └── podman / sudo / systemctl

Step 1: 加载配置
  ├── deploy.toml                 → 部署设置
  ├── secrets.toml                → ES / JWT / Git / LLM / Mail / Owner 凭据
  ├── suricata-llm-agent.toml     → 主配置
  ├── container_base/*.toml       → 基础镜像定义
  └── package_manager/*.toml      → 包管理器命令

Step 1.5: 预检验证 (Pre-flight Check)
  ├── JSON Schema 校验配置文件
  ├── 自动发现 x-deploy-file / x-deploy-dir 隐含引用
  └── 返回需加入构建上下文的 implicit_files / implicit_dirs

Step 2: 获取 sudo 权限（单次密码输入）

Step 3: 准备工作目录
  ├── 在 /dev/shm 创建临时目录
  ├── 复制 COPY_FILES / COPY_DIRS
  ├── 复制 deploy.toml 中的 extra_files
  └── 复制预检发现的隐含文件和目录

Step 3.5: 构建认证与凭据数据库
  ├── 创建宿主机 db_host_dir
  ├── 如已有 credentials.db，则复制到工作目录并保留既有用户/API Key
  ├── 缺少 Owner 时写入 secrets.toml 中的 Owner 用户
  └── upsert ES / JWT / Git / LLM / Mail 等服务凭据

Step 4: OAuth2 令牌配置（如需要）
  ├── 从工作目录 credentials.db 读取邮件 OAuth2 凭据
  ├── 尝试静默刷新已有 token cache
  └── 需要时启动交互式授权码流程并写回 credentials.db

Step 4.5: 部署 credentials.db
  └── 将工作目录中的 credentials.db 写入宿主机持久目录

Step 5: 渲染 Containerfile
  ├── 变量替换 (@image_url@, @maintainer@, @workdir@)
  └── 块替换 (@@ PM @@, @@ ARGS @@, @@ Extra Files @@, @@ Extra CMD @@)

Step 6: 渲染 Quadlet 服务文件
  ├── 变量替换 (@image_name@, @container_name@, @network@ 等)
  └── 块替换 (@@ Auth Volume @@, @@ Git Volume @@, @@ Environment @@)

Step 7: 构建容器镜像 (podman build)

Step 8: 安装 Quadlet 服务 + 重启 systemd
```

## 配置文件 deploy.toml

### [general]

| 选项 | 说明 |
|------|------|
| `deployment_work_dir` | 临时工作目录基础路径 |
| `project_config_dir` | 预定义配置目录（`configs/`） |
| `agent_config` | 主配置文件路径 |
| `constraints_dir` | JSON Schema 目录 |

### [deployment]

| 选项 | 说明 |
|------|------|
| `mode` | 部署模式（目前仅支持 `podman`） |

### [container]

| 选项 | 说明 |
|------|------|
| `base` | 基础镜像标识（如 `rhel10.0`、`rhel10.1`、`rhel10.2`、`debian13.1`、`debian13.2`、`debian13.3`、`debian13.4`），自动加载对应的预定义文件；当前配置模板使用 `rhel10.1` |
| `maintainer` | 镜像维护者信息 |
| `workdir` | 容器内工作目录（如 `/app`） |
| `extra_files` | 需额外烘焙的文件列表 |
| `extra_commands` | 构建时额外执行的命令列表 |
| `containerfile_args` | Containerfile ARG 参数列表 |

### [quadlet]

| 选项 | 说明 |
|------|------|
| `enable` | 是否安装 Quadlet 服务 |
| `container_name` | 容器名称 |
| `image_name` | 镜像名称 |
| `run_as` | 运行用户 UID（0=root） |
| `environment` | 环境变量字典 |

### [networking]

| 选项 | 说明 |
|------|------|
| `Network` | 容器网络（如 `elk-net`） |
| `PortMapping` | 端口映射配置（host_netseg, host_port, container_port） |
| `AddHost` | 自定义 /etc/hosts 条目 |

### [auth]

| 选项 | 说明 |
|------|------|
| `db_host_dir` | 宿主机上存放凭据数据库的持久目录（如 `/opt/suricata-llm-agent`），部署时自动创建并通过 Quadlet bind mount 挂载到容器 |

## 模板引擎

### 变量替换

使用 `@variable_name@` 语法：

```
@image_url@                                    → 简单变量
```

### 块替换

使用 `@@ BLOCK_NAME @@` 语法，占据单独一行：

```dockerfile
@@ PM @@           # → 包管理器命令（refresh + install）
@@ ARGS @@         # → Containerfile ARG 语句
@@ Extra Files @@  # → 额外 COPY 指令
@@ Extra CMD @@    # → 额外 RUN 指令
@@ Auth Volume @@  # → credentials.db 持久目录 bind mount
@@ Git Volume @@   # → Git 工作区占位块；当前返回空块，不生成宿主机 bind mount
@@ Environment @@  # → Quadlet 环境变量
```

空块（无内容）会删除整行。

### 模板文件

**Containerfile.in**：

```dockerfile
FROM @image_url@

LABEL maintainer=@maintainer@
LABEL description="This is a container image for running a Suricata LLM Agent with Python 3.12+."

WORKDIR @workdir@

@@ ARGS @@

COPY requirements.txt @workdir@/requirements.txt

@@ PM @@

RUN python3 -m venv @workdir@/venv
RUN @workdir@/venv/bin/pip install --no-cache-dir -r @workdir@/requirements.txt

COPY src/ @workdir@/suricata_llm_agent/
COPY suspicious_ja3.toml @workdir@/suspicious_ja3.toml
COPY suspicious_ja3s.toml @workdir@/suspicious_ja3s.toml
COPY configs/mail_providers/ @workdir@/configs/mail_providers/
COPY configs/capabilities/ @workdir@/configs/capabilities/

@@ Extra Files @@
@@ Extra CMD @@

CMD ["@workdir@/venv/bin/python3", "-m", "suricata_llm_agent.main", "--config", "@workdir@/@agent_config@"]
```

**suricata-llm-agent.container.in**（Quadlet 服务文件）：

```ini
[Unit]
Description=Suricata LLM Agent Service
After=elasticsearch.service
Requires=elasticsearch.service

[Container]
Image=@image_name@
ContainerName=@container_name@
Network=@network@
PublishPort=@port_mapping@
AddHost=@addhost@

@@ Auth Volume @@

@@ Git Volume @@

@@ Environment @@
StopTimeout=90
LogDriver=journald

# All service credentials are stored in credentials.db.
# No Podman secret or credential-bearing environment variable is required.

[Service]
TimeoutStartSec=300
TimeoutStopSec=90

[Install]
WantedBy=multi-user.target default.target
```

## 预检机制 (Pre-flight Check)

部署前自动验证所有配置文件是否符合 JSON Schema 约束：

| 校验对象 | Schema |
|---------|--------|
| `deploy.toml` | `deploy-config.schema.json` |
| `suricata-llm-agent.toml` | `agent-config.schema.json` |
| `secrets.toml` | `secrets.schema.json` |
| 容器基础配置 | `container-base.schema.json` |
| 包管理器配置 | `pm-config.schema.json` |
| 邮件提供商配置 | `mail-provider-config.schema.json` |

### 隐含文件自动发现

在 `agent-config.schema.json` 中，值类型为文件路径的属性使用自定义扩展字段 `x-deploy-file: true` 标记，目录路径使用 `x-deploy-dir: true` 标记。预检阶段遍历 schema，提取主配置中所有引用的文件和目录，将它们自动加入构建上下文。

这意味着当主配置中引用了新的外部文件（如 JA3 列表、prompt 模板、模型档案等），部署系统无需手动修改即可自动将它们烘焙进容器。

## 容器基础镜像

预定义在 `configs/container_base/` 下：

| 文件 | 镜像 | 包管理器 |
|------|------|---------|
| `rhel10.0.toml` | `registry.access.redhat.com/ubi10/ubi:10.0` | dnf |
| `rhel10.1.toml` | `registry.access.redhat.com/ubi10/ubi:10.1` | dnf |
| `rhel10.2.toml` | `registry.access.redhat.com/ubi10/ubi:10.2` | dnf |
| `debian13.1.toml` | `docker://debian:13.1` | apt |
| `debian13.2.toml` | `docker://debian:13.2` | apt |
| `debian13.3.toml` | `docker://debian:13.3` | apt |
| `debian13.4.toml` | `docker://debian:13.4` | apt |

在 `deploy.toml` 中通过 `container.base = "rhel10.1"` 等标识选择，无需关心镜像 URL 和包管理器细节。

## 凭据集中化

`secrets.toml` 中定义的所有凭据在部署时写入 `credentials.db`：

```
secrets.toml → 部署脚本 _provision_auth_db() → credentials.db credentials 表 / 用户表
```

启动时从数据库加载，无需 Podman secret 或凭据环境变量。执行器审计记录写入独立的 `auth-data/audit.db`（可由 `[executor].audit_db_path` 覆盖），随同一个宿主机持久目录独立保留；部署脚本只生成或更新 `credentials.db`。

### 管理的凭据

| secrets.toml 节 | 凭据 | credentials.db 键 | 说明 |
|-----------------|------|-------------------|------|
| `[elasticsearch]` | `username` / `password` | `es_user` / `es_pswd` | Elasticsearch 认证 |
| `[log_output]` | `username` / `password` | `log_es_user` / `log_es_pswd` | 日志输出 ES（可选，独立 ES 时使用） |
| `[auth]` | `jwt_secret` | `jwt_secret` | JWT 签名密钥 |
| `[auth.owner]` | `username` / `password` / `email` | — | Owner 用户（直接写入用户表） |
| `[git]` | `token` | `git_token` | GitHub Personal Access Token |
| `[llm]` | `api_key` | `llm_api_key` | 远程 LLM 后端 API Key（可选，也可在运行时通过 RMI 端点或环境变量配置） |
| `[mail]` | `client_id` / `client_secret` | `mail_client_id` / `mail_client_secret` | Outlook OAuth2 或 Gmail Basic Auth 凭据 |

> **注意**：`mail.client_id` 和 `mail.client_secret` 已从主配置文件 `suricata-llm-agent.toml` 迁移至 `secrets.toml`。主配置的 `[mail]` 节仅保留非敏感选项（`enable_notification`、`provider`、`sender`）。对于非容器化开发环境，仍可在主配置中临时设置 `client_id` / `client_secret`（仅限开发，运行时会被 `credentials.db` 覆盖）。

## Quadlet 服务安装

Quadlet 文件的安装路径取决于 `run_as` UID：

| UID | 路径 |
|-----|------|
| 0 (root) | `/etc/containers/systemd/` |
| 其他 | `~{user}/.config/containers/systemd/` |

安装后自动执行 `systemctl daemon-reload` 和服务重启。停止超时设为 90 秒，确保优雅关闭（发送关闭邮件、flush ES 缓冲等）。

## 目录排除规则

复制构建上下文时自动排除：

- `__pycache__/` 目录
- `*.egg-info/` 目录
- `*.pyc` 文件
