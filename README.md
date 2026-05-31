<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         README.md
Description:  Project overview with core features, dependencies, and quick start guide. (English version)
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
Date:         2026-05-31
-->

# Suricata LLM Agent

[中文](README.cn.md) | **English**

Suricata LLM Agent is a real-time Suricata IDS log analysis engine powered by
large language models. It reads Suricata `eve.json` events from Elasticsearch,
uses a local Ollama backend or an OpenAI-compatible backend (OpenAI, Azure
OpenAI, vLLM, and similar services) to generate automated threat assessments
and security recommendations, and writes the analysis results back to
Elasticsearch.

## Core Features

- **Real-time traffic analysis** - Batch-fetches unprocessed logs and calls LLMs concurrently to generate threat assessments and security recommendations.
- **Multiple memory modes** - Supports communication-pair, global, protocol-pair, and rolling-compaction memory for real-time correlation analysis.
- **Multi-level daily reports** - Supports hierarchical, communication-pair-only, and flat daily report modes, with HTML output and email delivery.
- **Hybrid LLM backends** - Routes models within the same instance to Ollama or OpenAI-compatible APIs, with vLLM metrics collection and request rate limiting.
- **Adaptive performance tuning** - Uses an EMA-based pressure-quality model to adjust model parameters based on LLM throughput, local GPU constraints, and optional cost budgets.
- **Remote Management Interface (RMI)** - Provides a FastAPI REST API for runtime status queries and manual daily report generation.
- **Mail queue** - Includes exponential backoff retries, persistent spooling, and dead-letter archiving.
- **Template-driven deployment** - Uses TOML configuration and JSON Schema preflight checks to generate Containerfile and Quadlet service files.
- **Configurable prompts** - Keeps LLM prompts fully externalized in TOML, with separate templates for real-time analysis and daily reports.
- **Authentication and authorization (U-A-P)** - Provides a role-based User-Actor-Permission model (Owner / Administrator / Agent / Watcher), JWT and API Key authentication, and SSE log streaming.
- **Executor subsystem** - Provides declarative TOML capability registration, a policy engine (role checks, parameter validation, rate limits), a PathGuard filesystem sandbox, and SQLite audit logs.
- **Agent mode** - Adds a ReAct orchestrator for LLM tool calling, with backend capability detection and fallback to Pipeline mode.
- **Git / GitHub integration** - Creates issues, commits changes, and opens PRs through the executor; also supports automatic Suricata rule generation and validation.
- **Centralized credential management** - Stores users, API keys, ES passwords, GitHub tokens, LLM API keys, mail credentials, and OAuth2 caches in `credentials.db`.
- **Fine-tuning sample collection** - Optionally records real-time analysis system/user/response triples and exports JSONL after RMI-based labeling.

## Requirements

- Python >= 3.12
- Elasticsearch for log storage and querying
- [Ollama](https://ollama.com/) when using a local backend
- An OpenAI-compatible API service when using a remote backend or vLLM
- Podman + systemd for containerized deployment

## Quick Start

### 1. Install

```bash
# Clone the project
git clone <repo-url>
cd suricata_llm_agent_pkg

# Install dependencies (uv is recommended and creates/updates the project .venv)
uv sync

# Or use pip with an explicit virtual environment
python -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### 2. Configure

Before running the service, copy the configuration templates to the project root
and fill in real values:

```bash
cp config_templates/*.toml ./
```

Then edit the configuration files and replace placeholders such as `CHANGE_ME`
and `YOUR_CLIENT_ID` with your real values. Root-level configuration files are
ignored by `.gitignore` and will not be committed.

The main configuration file is `suricata-llm-agent.toml`. It defines
Elasticsearch connectivity, event filters, LLM parameters, daily report
settings, mail configuration, and other runtime options.

```toml
# Minimal core settings
[elasticsearch]
host = "https://your-es-host:9200"
user = "your-es-user"       # Container deployment can load this from credentials.db
password = "your-es-password"
index_pattern = "suricata-eve-*"

[llm.backend]
type = "ollama"       # Or "openai"
# base_url = "https://api.example.com/v1"   # Required for the openai backend

[ollama]
base_url = "http://localhost:11434"

[perf]
model_profiles_file = "ModelProfiles.toml"
```

Related configuration files:

| File | Purpose |
|------|---------|
| `suricata-llm-agent.toml` | Main configuration file |
| `llm_prompt.toml` | LLM prompt templates |
| `ModelProfiles.toml` | Model performance profiles |
| `daily_report_llm_conf.toml` | Dedicated daily-report LLM parameters |
| `suspicious_ja3.toml` | Suspicious JA3 client fingerprint list |
| `suspicious_ja3s.toml` | Suspicious JA3S server fingerprint list |
| `secrets.toml` | Service credentials written to `credentials.db` during deployment |
| `deploy.toml` | Deployment system configuration |

See [docs/en/configuration.md](docs/en/configuration.md).

### 3. Run

```bash
# Run directly
.venv/bin/python -m src.main

# Or deploy in a container (recommended)
.venv/bin/python deploy.py
```

### 4. Containerized Deployment

The deployment system performs configuration preflight checks, obtains sudo,
prepares the build context, creates or updates `credentials.db`, provisions
OAuth2 tokens, renders Containerfile and Quadlet files, builds the image, and
installs/restarts the systemd service.

```bash
.venv/bin/python deploy.py
```

See [docs/en/deployment.md](docs/en/deployment.md).

## Project Layout

```text
suricata_llm_agent_pkg/
├── src/                         # SLA runtime source code
│   ├── main.py                  # Startup orchestration and main loop
│   ├── config.py                # Configuration loading, credentials, model profiles
│   ├── processor.py             # Real-time batch processing and Agent/Pipeline routing
│   ├── llm_handler.py           # LLM calls, memory, JSON parsing, Agent identity
│   ├── orchestrator.py          # Agent-mode ReAct loop
│   ├── daily_report.py          # Daily reports, rule generation, HTML output
│   ├── rmi.py                   # FastAPI remote management interface
│   ├── es_client.py             # Elasticsearch reads and writes
│   ├── pre_process.py           # ES query construction and event filtering
│   ├── perf_cacl.py             # Adaptive performance tuning
│   ├── auth/                    # U-A-P users, roles, JWT, API keys, SSE logs
│   ├── executor/                # Capability registry, policy, PathGuard, audit, handlers
│   ├── backends/                # Ollama / OpenAI-compatible backends and rate limiting
│   └── mailer/                  # Mail sending, OAuth2, retry queue, recipient resolution
├── configs/                     # Capabilities, schemas, base images, package managers, templates
│   ├── capabilities/            # Executor capability declarations
│   ├── constraints/             # JSON Schema preflight rules
│   ├── container_base/          # Container base image definitions
│   ├── package_manager/         # Package-manager command definitions
│   ├── mail_providers/          # Mail provider configuration
│   └── templates/               # Containerfile and Quadlet templates
├── deploy/                      # Modular deployment implementation
├── docs/                        # Project documentation
├── tests/                       # Unit tests
├── deploy.py                    # Deployment entry point
└── *.toml                       # Main, model, prompt, deployment, and secret configs
```

## Documentation

| Document | Content |
|----------|---------|
| [Architecture Overview](docs/en/architecture.md) | System architecture, module relationships, thread model, and data flow |
| [Configuration Reference](docs/en/configuration.md) | Detailed reference for all configuration files |
| [Deployment Guide](docs/en/deployment.md) | Deployment workflow, template engine, and preflight checks |
| [Authentication and Authorization](docs/en/auth.md) | U-A-P role model, JWT/API Key authentication, and endpoint protection |
| [Executor Subsystem](docs/en/executor.md) | Capability declarations, policy engine, PathGuard, and audit logs |
| [Agent Mode](docs/en/agent-mode.md) | ReAct loop, tool calling, mode detection, and fallback |
| [Git Integration](docs/en/git-integration.md) | Automatic issue/PR creation, rule generation, and repository management |
| [Performance Tuning](docs/en/performance-tuning.md) | Adaptive performance algorithm, model profiles, and pressure-quality model |
| [Remote Management Interface](docs/en/rmi.md) | RMI REST API endpoints and usage |
| [Daily Report System](docs/en/daily-report.md) | Multi-level daily report generation flow and configuration |
| [Mail System](docs/en/mail-system.md) | Mail sending, retry queue, and OAuth2 authentication |
| [LLM Prompt Configuration](docs/en/llm-prompt-config.md) | Prompt template structure and customization |

## License

MIT License - Capri XXI (qxwzj@hotmail.com)
