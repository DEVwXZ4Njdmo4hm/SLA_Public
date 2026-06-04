<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         README_cn.md
Description:  Project overview with core features, dependencies, and quick start guide. (Chinese version)
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
Date:         2026-03-22
-->

# Suricata LLM Agent

**中文** | [English](README.md)


基于大语言模型的 Suricata IDS 日志实时分析引擎。从 Elasticsearch 中提取 Suricata 产生的 `eve.json` 日志，利用本地 Ollama、通用 OpenAI 兼容后端（OpenAI / Azure OpenAI / vLLM 等）或原生 DeepSeek API 后端进行自动化威胁评估、安全建议生成，并将分析结果回写至 Elasticsearch。

## 核心特性

- **实时流量分析** — 批量拉取未处理日志，并发调用 LLM 生成威胁评估和安全建议
- **多模式记忆** — 支持通信对、全局、协议-通信对与滚动压缩记忆，用于实时关联分析
- **多级日报生成** — 支持层级、通信对级和扁平日报分析模式，输出 HTML 日报并邮件发送
- **混合 LLM 后端** — 同一实例可按模型路由到 Ollama、OpenAI 兼容 API 或原生 DeepSeek API 后端，并支持 vLLM 指标采集和请求限速
- **自适应性能调优** — 基于 EMA 的压力-质量模型，结合 LLM 吞吐量、本地 GPU 约束和可选成本预算调整模型参数
- **远程管理接口 (RMI)** — FastAPI REST API，支持运行时状态查询和手动触发日报
- **邮件队列** — 指数退避重试 + 持久化暂存 + 死信归档
- **模板化部署** — 基于 TOML 配置 + JSON Schema 预检，自动生成 Containerfile 和 Quadlet 服务文件
- **可配置 Prompt** — LLM 提示词完全外置于 TOML 配置，支持实时分析和日报的独立 prompt 模板
- **认证与授权 (U-A-P)** — 基于角色的用户-角色-权限模型（Owner / Administrator / Agent / Watcher），JWT + API Key 双轨认证，SSE 日志流
- **执行器子系统** — 声明式能力注册（TOML）、策略引擎（角色检查 + 参数校验 + 速率限制）、PathGuard 文件系统沙盒、SQLite 审计日志
- **Agent 模式** — 支持 LLM tool calling 的 ReAct 循环编排器，按后端检测模型能力并回退至 Pipeline 模式
- **Git / GitHub 集成** — 通过执行器创建 Issue、提交 commit、按策略发起 PR；支持 Suricata 规则自动生成与验证
- **凭据集中管理** — 用户、API Key、ES 密码、GitHub Token、LLM API Key、邮件认证凭据与 OAuth2 缓存统一存储于 `credentials.db`
- **微调样本采集** — 可选记录实时分析的 system/user/response 三元组，经 RMI 标注后导出 JSONL

## 依赖

- Python ≥ 3.12
- Elasticsearch（用于日志存储和查询）
- [Ollama](https://ollama.com/)（选择本地后端时使用）
- OpenAI 兼容 API 服务或 DeepSeek API Key（选择远程后端时使用）
- Podman + systemd（用于容器化部署）

## 快速开始

### 1. 安装

```bash
# 克隆项目
git clone <repo-url>
cd suricata_llm_agent_pkg

# 安装依赖（推荐使用 uv，会创建/更新项目 .venv）
uv sync

# 或使用 pip + 显式虚拟环境
python -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### 2. 配置

运行前需要将配置模板复制到项目根目录并填入真实值：

```bash
cp config_templates/*.toml ./
```

然后编辑各配置文件，替换占位符（`CHANGE_ME`、`YOUR_CLIENT_ID` 等）为你的实际值。根目录下的配置文件已被 `.gitignore` 忽略，不会被提交。

核心配置文件为 `suricata-llm-agent.toml`，它定义了 Elasticsearch 连接、事件过滤规则、LLM 参数、日报设置、邮件配置等所有运行时选项。

```toml
# 最基本的配置项
[elasticsearch]
host = "https://your-es-host:9200"
user = "your-es-user"       # 容器部署可由 credentials.db 提供
password = "your-es-password"
index_pattern = "suricata-eve-*"

[llm.backend]
type = "ollama"       # 或 "openai" / "deepseek"
# base_url = "https://api.example.com"      # openai 后端必填；deepseek 可省略

[ollama]
base_url = "http://localhost:11434"

[perf]
model_profiles_file = "ModelProfiles.toml"
```

相关配置文件一览：

| 文件 | 用途 |
|------|------|
| `suricata-llm-agent.toml` | 主配置文件 |
| `llm_prompt.toml` | LLM 提示词模板 |
| `ModelProfiles.toml` | 模型性能基准档案 |
| `daily_report_llm_conf.toml` | 日报专用 LLM 参数 |
| `suspicious_ja3.toml` | 可疑 JA3 客户端指纹列表 |
| `suspicious_ja3s.toml` | 可疑 JA3S 服务端指纹列表 |
| `secrets.toml` | 部署阶段写入 `credentials.db` 的服务凭据 |
| `deploy.toml` | 部署系统配置 |

详见 [docs/configuration.md](docs/cn/configuration.md)。

### 3. 运行

```bash
# 直接运行
.venv/bin/python -m src.main

# 或在容器中部署（推荐）
.venv/bin/python deploy.py
```

### 4. 容器化部署

部署系统会自动完成：配置预检 → 获取 sudo → 准备构建上下文 → 生成/更新 `credentials.db` → OAuth2 令牌配置 → 生成 Containerfile 与 Quadlet → 构建镜像 → 安装并重启 systemd 服务。

```bash
.venv/bin/python deploy.py
```

详见 [docs/cn/deployment.md](docs/cn/deployment.md)。

## 项目结构

```
suricata_llm_agent_pkg/
├── src/                         # SLA 运行期源代码
│   ├── main.py                  # 启动编排与主循环
│   ├── config.py                # 配置加载、凭据加载、模型档案
│   ├── processor.py             # 实时批处理、Agent/Pipeline 分流
│   ├── llm_handler.py           # LLM 调用、记忆、JSON 解析、Agent identity
│   ├── orchestrator.py          # Agent 模式 ReAct 循环
│   ├── daily_report.py          # 日报、规则生成、HTML 输出
│   ├── rmi.py                   # FastAPI 远程管理接口
│   ├── es_client.py             # Elasticsearch 读写
│   ├── pre_process.py           # ES 查询构建与事件过滤
│   ├── perf_cacl.py             # 自适应性能调优
│   ├── auth/                    # U-A-P 用户、角色、JWT、API Key、SSE 日志
│   ├── executor/                # 能力注册、策略、PathGuard、审计、handler
│   ├── backends/                # Ollama / OpenAI 兼容 / DeepSeek 后端与限速
│   └── mailer/                  # 邮件发送、OAuth2、重试队列、收件人解析
├── configs/                     # 能力、Schema、镜像基础、包管理器、模板配置
│   ├── capabilities/            # Executor capability 声明
│   ├── constraints/             # JSON Schema 预检规则
│   ├── container_base/          # 容器基础镜像定义
│   ├── package_manager/         # 包管理器命令定义
│   ├── mail_providers/          # 邮件提供商配置
│   └── templates/               # Containerfile 与 Quadlet 模板
├── deploy/                      # 模块化部署实现
├── docs/                        # 项目文档
├── tests/                       # 单元测试
├── deploy.py                    # 部署脚本入口
└── *.toml                       # 主配置、模型档案、Prompt、部署与密钥配置
```

## 文档

| 文档 | 内容 |
|------|------|
| [架构概览](docs/cn/architecture.md) | 系统架构、模块关系、线程模型、数据流 |
| [配置参考](docs/cn/configuration.md) | 所有配置文件的详细说明 |
| [部署指南](docs/cn/deployment.md) | 部署系统的使用、模板引擎、预检机制 |
| [认证与授权](docs/cn/auth.md) | U-A-P 角色模型、JWT/API Key 认证、端点保护 |
| [执行器子系统](docs/cn/executor.md) | 能力声明、策略引擎、PathGuard、审计日志 |
| [Agent 模式](docs/cn/agent-mode.md) | ReAct 循环、tool calling、模式检测与回退 |
| [Git 集成](docs/cn/git-integration.md) | Issue/PR 自动创建、规则生成、仓库管理 |
| [性能调优](docs/cn/performance-tuning.md) | 自适应性能算法、模型档案、压力-质量模型 |
| [远程管理接口](docs/cn/rmi.md) | RMI REST API 端点和用法 |
| [日报系统](docs/cn/daily-report.md) | 多级日报生成流程和配置 |
| [邮件系统](docs/cn/mail-system.md) | 邮件发送、队列重试、OAuth2 认证 |
| [LLM Prompt 配置](docs/cn/llm-prompt-config.md) | Prompt 模板结构和自定义 |

## 许可证

MIT License — Capri XXI (qxwzj@hotmail.com)
