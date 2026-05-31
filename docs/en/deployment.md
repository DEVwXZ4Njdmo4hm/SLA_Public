<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         deployment.md
Description:  Deployment guide covering prerequisites, workflow, and configuration steps.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# Deployment Guide

## Overview

The deployment system (`deploy.py`) is an interactive containerized deployment
tool. It generates Containerfile and Quadlet service files from TOML
configuration and templates, prepares the build context, provisions the
credential database, builds the image, and installs the systemd service.

The full flow is: **configuration preflight -> sudo acquisition -> build context
preparation -> credentials.db creation/update -> OAuth2 token provisioning ->
template rendering -> image build -> Quadlet installation and service restart**.

## Prerequisites

- `podman` as the container runtime
- `sudo` for privilege elevation
- `systemctl` for systemd service management
- Interactive terminal. The deployment script checks for a TTY and refuses to
  run in a non-interactive environment.

## Run

```bash
python deploy.py
```

The script interactively guides the deployment process, including sudo password
entry and optional OAuth2 authorization.

## Deployment Flow

```text
Step 0: Check runtime environment
  `-- podman / sudo / systemctl

Step 1: Load configuration
  |-- deploy.toml                 -> deployment settings
  |-- secrets.toml                -> ES / JWT / Git / LLM / Mail / Owner credentials
  |-- suricata-llm-agent.toml     -> main configuration
  |-- container_base/*.toml       -> base image definitions
  `-- package_manager/*.toml      -> package manager commands

Step 1.5: Pre-flight Check
  |-- JSON Schema validation for configuration files
  |-- Automatic discovery of implicit x-deploy-file / x-deploy-dir references
  `-- Return implicit_files / implicit_dirs to add to the build context

Step 2: Acquire sudo privileges with one password prompt

Step 3: Prepare work directory
  |-- Create a temporary directory under /dev/shm
  |-- Copy COPY_FILES / COPY_DIRS
  |-- Copy extra_files from deploy.toml
  `-- Copy implicit files and directories discovered by preflight

Step 3.5: Build authentication and credential database
  |-- Create host db_host_dir
  |-- If credentials.db already exists, copy it to the work directory and preserve users/API Keys
  |-- Write Owner user from secrets.toml when Owner is missing
  `-- Upsert ES / JWT / Git / LLM / Mail service credentials

Step 4: OAuth2 token provisioning when needed
  |-- Read mail OAuth2 credentials from work-directory credentials.db
  |-- Try silent refresh of existing token cache
  `-- If needed, run interactive authorization-code flow and write back to credentials.db

Step 4.5: Deploy credentials.db
  `-- Write the work-directory credentials.db to the host persistent directory

Step 5: Render Containerfile
  |-- Variable replacement (@image_url@, @maintainer@, @workdir@)
  `-- Block replacement (@@ PM @@, @@ ARGS @@, @@ Extra Files @@, @@ Extra CMD @@)

Step 6: Render Quadlet service file
  |-- Variable replacement (@image_name@, @container_name@, @network@, and others)
  `-- Block replacement (@@ Auth Volume @@, @@ Git Volume @@, @@ Environment @@)

Step 7: Build container image (podman build)

Step 8: Install Quadlet service + restart systemd
```

## deploy.toml Configuration

### [general]

| Option | Description |
|--------|-------------|
| `deployment_work_dir` | Base path for temporary work directories |
| `project_config_dir` | Predefined configuration directory (`configs/`) |
| `agent_config` | Main configuration file path |
| `constraints_dir` | JSON Schema directory |

### [deployment]

| Option | Description |
|--------|-------------|
| `mode` | Deployment mode. Currently only `podman` is supported |

### [container]

| Option | Description |
|--------|-------------|
| `base` | Base image identifier, such as `rhel10.1`, `rhel10.2`, `debian13.3`, or `debian13.4`; the corresponding predefined file is loaded automatically. The current template uses `rhel10.1` |
| `maintainer` | Image maintainer information |
| `workdir` | Container work directory, such as `/app` |
| `extra_files` | Additional files to bake into the image |
| `extra_commands` | Additional commands to run during build |
| `containerfile_args` | Containerfile ARG parameter list |

### [quadlet]

| Option | Description |
|--------|-------------|
| `enable` | Whether to install the Quadlet service |
| `container_name` | Container name |
| `image_name` | Image name |
| `run_as` | Runtime user UID, where 0 means root |
| `environment` | Environment variable dictionary |

### [networking]

| Option | Description |
|--------|-------------|
| `Network` | Container network, such as `elk-net` |
| `PortMapping` | Port mapping configuration: host_netseg, host_port, container_port |
| `AddHost` | Custom `/etc/hosts` entries |

### [auth]

| Option | Description |
|--------|-------------|
| `db_host_dir` | Persistent host directory for the credential database, such as `/opt/suricata-llm-agent`; created during deployment and mounted into the container by Quadlet |

## Template Engine

### Variable Replacement

Variables use `@variable_name@` syntax:

```text
@image_url@                                    -> simple variable
```

### Block Replacement

Blocks use `@@ BLOCK_NAME @@` syntax and occupy a full line:

```dockerfile
@@ PM @@           # -> package manager commands: refresh + install
@@ ARGS @@         # -> Containerfile ARG statements
@@ Extra Files @@  # -> extra COPY instructions
@@ Extra CMD @@    # -> extra RUN instructions
@@ Auth Volume @@  # -> credentials.db persistent-directory bind mount
@@ Git Volume @@   # -> Git workspace placeholder; currently empty, no host bind mount
@@ Environment @@  # -> Quadlet environment variables
```

Empty blocks delete the whole line.

### Template Files

**Containerfile.in**:

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

**suricata-llm-agent.container.in** (Quadlet service file):

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

## Preflight Check

Before deployment, all configuration files are validated against JSON Schema:

| Target | Schema |
|--------|--------|
| `deploy.toml` | `deploy-config.schema.json` |
| `suricata-llm-agent.toml` | `agent-config.schema.json` |
| `secrets.toml` | `secrets.schema.json` |
| Container base config | `container-base.schema.json` |
| Package manager config | `pm-config.schema.json` |
| Mail provider config | `mail-provider-config.schema.json` |

### Implicit File Discovery

In `agent-config.schema.json`, properties whose values are file paths are marked
with the custom extension `x-deploy-file: true`, and directory paths are marked
with `x-deploy-dir: true`. During preflight, the schema is traversed and all
files and directories referenced by the main configuration are added to the
build context automatically.

This means that when the main configuration references a new external file, such
as a JA3 list, prompt template, or model profile, the deployment system can bake
it into the container without manual edits.

## Container Base Images

Predefined under `configs/container_base/`:

| File | Image | Package manager |
|------|-------|-----------------|
| `rhel10.1.toml` | `registry.access.redhat.com/ubi10/ubi:10.1` | dnf |
| `rhel10.2.toml` | `registry.access.redhat.com/ubi10/ubi:10.2` | dnf |
| `debian13.3.toml` | `docker://debian:13.3` | apt |
| `debian13.4.toml` | `docker://debian:13.4` | apt |

Select an image in `deploy.toml` with an identifier such as
`container.base = "rhel10.1"`. The image URL and package-manager details are
loaded automatically.

## Centralized Credentials

All credentials defined in `secrets.toml` are written to `credentials.db` during
deployment:

```text
secrets.toml -> deployment script _provision_auth_db() -> credentials.db credentials table / users table
```

Startup loads credentials from the database, so Podman secrets or
credential-bearing environment variables are not required. Executor audit
records are written to a separate `auth-data/audit.db` by default, or to the path
set by `[executor].audit_db_path`, and are kept independently in the same host
persistent directory. The deployment script creates or updates only
`credentials.db`.

### Managed Credentials

| secrets.toml section | Credential | credentials.db key | Description |
|----------------------|------------|--------------------|-------------|
| `[elasticsearch]` | `username` / `password` | `es_user` / `es_pswd` | Elasticsearch authentication |
| `[log_output]` | `username` / `password` | `log_es_user` / `log_es_pswd` | Optional separate ES credentials for log output |
| `[auth]` | `jwt_secret` | `jwt_secret` | JWT signing secret |
| `[auth.owner]` | `username` / `password` / `email` | - | Owner user, written directly to the users table |
| `[git]` | `token` | `git_token` | GitHub Personal Access Token |
| `[llm]` | `api_key` | `llm_api_key` | Remote LLM backend API Key; optional and also configurable at runtime through RMI or environment variable |
| `[mail]` | `client_id` / `client_secret` | `mail_client_id` / `mail_client_secret` | Outlook OAuth2 or Gmail Basic Auth credentials |

> **Note**: `mail.client_id` and `mail.client_secret` have moved from
> `suricata-llm-agent.toml` to `secrets.toml`. The main `[mail]` section keeps
> only non-sensitive options: `enable_notification`, `provider`, and `sender`.
> For non-container development, `client_id` and `client_secret` may still be set
> temporarily in the main config for development only; runtime database values
> take precedence.

## Quadlet Service Installation

The Quadlet installation path depends on `run_as` UID:

| UID | Path |
|-----|------|
| 0 (root) | `/etc/containers/systemd/` |
| Other | `~{user}/.config/containers/systemd/` |

After installation, the script automatically runs `systemctl daemon-reload` and
restarts the service. Stop timeout is set to 90 seconds to support graceful
shutdown, including shutdown email and ES buffer flush.

## Directory Exclusion Rules

Build-context copying automatically excludes:

- `__pycache__/` directories
- `*.egg-info/` directories
- `*.pyc` files
