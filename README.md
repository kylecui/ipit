# TIRE — Threat Intelligence Reasoning Engine

A multi-source threat intelligence analysis and reasoning engine for IP observables, featuring evidence-driven verdicts, semantic service recognition, and LLM-enhanced narrative reports.

> **Note**: 中文文档请参阅下文。 (Chinese documentation is available below.)

## Key Features

- **11 Intelligence Sources**: AbuseIPDB, AlienVault OTX, GreyNoise, VirusTotal (including passive DNS/resolutions), Shodan, RDAP, Reverse DNS, Honeynet, Internal Flow, **ThreatBook**, and **TianJi YouMeng**.
- **Admin Portal**: Centralized dashboard for user management, plugin configuration, policy groups, and real-time usage statistics.
- **API Key Management**: Support for both shared admin-configured keys and personal user keys, encrypted at rest using Fernet.
- **LLM Management**: Flexible LLM configurations (shared or personal) for generating narrative reports.
- **Persistent Result Storage**: Queries are stored as snapshots in `storage/results.db`, allowing for historical comparison and timeline views.
- **Historical Comparison**: Side-by-side diffing of snapshots and reports to track changes in threat posture over time.
- **Plugin-based Analysis Pipeline**: A structured flow from Plugins → Enrichers → Analyzers → Verdict → Reporters.
- **Community Plugin Platform**: Upload and run community plugins in isolated sandboxes to protect platform stability and secrets.
- **Semantic Service Recognition**: YAML-driven service catalog identifies cloud providers, CDNs, and Microsoft/Google services to reduce false positives.
- **Evidence-driven Verdicts**: Every verdict includes scored evidence items with detailed explanations, ensuring transparency beyond simple numbers.
- **Scoring System**: A 0–100 scale where higher values indicate greater danger. Thresholds: Low (0–20), Medium (21–45), High (46–75), and Critical (76–100).
- **LLM-enhanced Narrative Reports**: On-demand AI-generated threat intelligence reports with contextual analysis, powered by OpenAI-compatible APIs.
- **Bilingual i18n (EN/ZH)**: Full internationalization support for the Web UI, CLI output, and reports.
- **4 Input Modes**: Supports CLI commands, REST API, Web Dashboard, and CSV Batch processing.
- **Docker Deployment**: Production-ready Docker Compose setup with health checks and persistent volumes.

## Architecture Overview

```
       Admin Portal Layer (User/Key/Policy/Stats)
                    ↓
Input Layer (CLI / API / Web UI / Batch)
                    ↓
      Query Orchestration (QueryEngine)
                    ↓
Plugins → Enrichers → Analyzers → Verdict → Reporters
   ↑           ↑            ↑          ↑         ↑
Dynamic    Semantic    Multi-layer  Evidence  Multi-format
Sources    Tags        Analysis     Fusion    Output
```

## Quick Start

### Local Development

```bash
git clone <repository-url>
cd ipit

# Create virtual environment (uv recommended)
uv venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
uv pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your API keys and security secrets:
# ADMIN_PASSWORD, SESSION_SECRET_KEY, TIRE_FERNET_KEY
```

### Docker Deployment (Recommended for Production)

```bash
cp .env.example .env
# Edit .env with your configuration
docker compose up -d
# Open http://localhost:8000/ (or /v2 if ROOT_PATH is set)
```

## Usage

### CLI Commands

TIRE provides four primary commands, all supporting `--format` (json/md/cli), `--lang` (en/zh), and `--refresh` (to bypass cache).

- `lookup`: Quick IP lookup.
- `report`: Generate a detailed report.
- `analyze`: Contextual analysis.
- `batch`: Process multiple observables from a CSV file.

Example:
```bash
uv run python -m app.main lookup 1.1.1.1 --format cli
```

### REST API Endpoints

- `GET  /api/v1/ip/{ip}` — IP lookup.
- `POST /api/v1/analyze/ip` — Contextual analysis.
- `POST /api/v1/report/generate` — Generate narrative report.
- `GET  /api/v1/results/{ip}/history` — Result history.
- `GET  /api/v1/results/snapshots/{snapshot_id}` — Snapshot detail.
- `GET  /api/v1/results/{ip}/compare` — Compare snapshots.
- `GET  /api/v1/reports/{ip}/history` — Report history.
- `GET  /api/v1/reports/{report_id}` — Report detail.
- `GET  /api/v1/me/snapshots` — My snapshot history.
- `GET  /api/v1/me/reports` — My report history.
- `GET  /api/v1/debug/sources/{ip}` — Debug raw data.
- `GET  /healthz`, `GET /readyz` — Health checks.

### Web Dashboard

Access the dashboard at `http://localhost:8000/`. The admin portal is available at `/admin/` for managing users, keys, and viewing statistics.

## Configuration

### Environment Variables

**Security & Admin**
- `ADMIN_PASSWORD`: Default admin password.
- `SESSION_SECRET_KEY`: Secret key for session management.
- `TIRE_FERNET_KEY`: Encryption key for API keys at rest.

**API Keys**
- `THREATBOOK_API_KEY`: API key for ThreatBook.
- `TIANJIYOUMENG_API_KEY`: API key for TianJi YouMeng.
- (Other keys: ABUSEIPDB, OTX, GREYNOISE, VT, SHODAN)

**Application**
- `ROOT_PATH`: Sub-path for the application (e.g., `/v2`).
- `RESULT_STALENESS_DAYS`: Days before a result is considered stale (default: 7).

## Project Structure

```
├── app/                    # Application core
├── admin/                  # Admin portal (routes, auth, templates)
├── plugins/                # Plugin platform (builtin, community, sandbox)
├── storage/                # Persistence (results.db, admin.db)
├── cache/                  # TTL cache layer
├── normalizers/            # Data standardization
├── enrichers/              # Semantic tagging
├── analyzers/              # Multi-layer analysis
├── reporters/              # Output formatters
├── models/                 # Pydantic data models
├── rules/                  # YAML rule files
├── templates/              # Jinja2 HTML templates
├── locales/                # i18n translation files
└── docs/                   # Extended documentation
```

## Documentation

- [Quick Start Guide](docs/quickstart.md)
- [Deployment Guide](docs/deployment.md)
- [Configuration Reference](docs/configuration.md)
- [Admin Portal Guide](docs/admin-guide.md)
- [Troubleshooting](docs/troubleshooting.md)
- [V2 Plugin Architecture](docs/V2_PLUGIN_ARCHITECTURE.md)

## Design Principles

1. **Plugins are self-contained**: Plugins gather source data and emit evidence through a stable plugin contract.
2. **All scoring in Analyzers**: Scoring logic is centralized within the analyzer components.
3. **Analyzers emit evidence**: Every analyzer must produce evidence items for its findings.
4. **Semantic tag driven**: Use YAML rules to drive semantic tagging whenever possible.
5. **Fault tolerance**: The query orchestration must tolerate failures from individual collectors.
6. **Reporters have no business logic**: Reporters are responsible for presentation only and contain no business logic.
7. **Sandbox untrusted plugins**: Community plugins must not be able to crash or compromise the platform.
8. **Optional context**: Contextual analysis must remain optional for all lookups.
9. **Batch fault tolerance**: Batch processing must be resilient to individual item failures.
10. **No sensitive config in logs**: Never print sensitive configurations or API keys in logs.
11. **Allow inconclusive output**: The engine must support and handle inconclusive or uncertain results.

## License

Open source. See LICENSE for details.

---

# TIRE — 威胁情报推理引擎

多源威胁情报分析与推理引擎，支持证据驱动的判决、语义服务识别以及 LLM 增强的叙述性报告。

## 核心功能

- **11 个情报源**：AbuseIPDB, AlienVault OTX, GreyNoise, VirusTotal, Shodan, RDAP, Reverse DNS, Honeynet, Internal Flow, **微步在线 (ThreatBook)**, **天际友盟 (TianJi YouMeng)**。
- **管理后台**：集中化的仪表板，用于用户管理、插件配置、策略组及实时使用统计。
- **API 密钥管理**：支持管理员配置的共享密钥和用户个人密钥，使用 Fernet 进行加密存储。
- **LLM 管理**：灵活的 LLM 配置（共享或个人），用于生成叙述性报告。
- **持久化存储**：查询结果以快照形式存储在 `storage/results.db` 中，支持历史对比和时间轴视图。
- **历史对比**：支持快照和报告的侧向对比，追踪威胁态势随时间的变化。
- **插件化分析流水线**：插件 → 丰富器 → 分析器 → 判决 → 报告器。
- **社区插件平台**：支持上传并在隔离沙箱中运行社区插件，保护平台稳定与密钥安全。
- **语义服务识别**：基于 YAML 的服务目录，识别云厂商、CDN 及 Microsoft/Google 服务，减少误报。
- **证据驱动判决**：每个判决均包含带分数的证据项及详细说明。
- **评分系统**：0–100 分制。阈值：低 (0–20), 中 (21–45), 高 (46–75), 严重 (76–100)。
- **LLM 增强报告**：按需生成 AI 威胁情报报告，支持上下文分析。
- **双语支持 (EN/ZH)**：Web UI、CLI 输出及报告全面支持中英文。
- **4 种输入模式**：CLI、REST API、Web 仪表板、CSV 批量处理。
- **Docker 部署**：生产就绪的 Docker Compose 配置，含健康检查与持久化卷。

## 架构概览

```
       管理后台层 (用户/密钥/策略/统计)
                    ↓
输入层 (CLI / API / Web UI / Batch)
                    ↓
      查询编排 (QueryEngine)
                    ↓
插件 → 丰富器 → 分析器 → 判决 → 报告器
   ↑           ↑            ↑          ↑         ↑
动态    语义    多层        证据      多格式
数据源  标签    分析        融合      输出
```

## 快速开始

### 本地开发

```bash
git clone <repository-url>
cd ipit
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
cp .env.example .env
# 编辑 .env 配置 API 密钥及安全密钥:
# ADMIN_PASSWORD, SESSION_SECRET_KEY, TIRE_FERNET_KEY
```

### Docker 部署

```bash
cp .env.example .env
docker compose up -d
# 访问 http://localhost:8000/ (若设置了 ROOT_PATH 则访问对应子路径)
```

## 使用说明

### CLI 命令

支持 `--format` (json/md/cli), `--lang` (en/zh), `--refresh` (跳过缓存)。

- `lookup`: 快速 IP 查询。
- `report`: 生成详细报告。
- `analyze`: 上下文分析。
- `batch`: 批量处理 CSV 文件。

### REST API 接口

- `GET  /api/v1/ip/{ip}` — IP 查询。
- `POST /api/v1/analyze/ip` — 上下文分析。
- `POST /api/v1/report/generate` — 生成叙述性报告。
- `GET  /api/v1/results/{ip}/history` — 结果历史。
- `GET  /api/v1/results/snapshots/{snapshot_id}` — 快照详情。
- `GET  /api/v1/results/{ip}/compare` — 快照对比。
- `GET  /api/v1/reports/{ip}/history` — 报告历史。
- `GET  /api/v1/reports/{report_id}` — 报告详情。
- `GET  /api/v1/me/snapshots` — 我的快照历史。
- `GET  /api/v1/me/reports` — 我的报告历史。
- `GET  /api/v1/debug/sources/{ip}` — 调试原始数据。
- `GET  /healthz`, `GET /readyz` — 健康检查。

## 配置说明

### 环境变量

**安全与管理**
- `ADMIN_PASSWORD`: 默认管理员密码。
- `SESSION_SECRET_KEY`: 会话管理密钥。
- `TIRE_FERNET_KEY`: API 密钥加密存储密钥。

**API 密钥**
- `THREATBOOK_API_KEY`: 微步在线 API 密钥。
- `TIANJIYOUMENG_API_KEY`: 天际友盟 API 密钥。

**应用配置**
- `ROOT_PATH`: 应用子路径 (如 `/v2`)。
- `RESULT_STALENESS_DAYS`: 结果过期天数 (默认: 7)。

## 项目结构

```
├── app/                    # 应用核心
├── admin/                  # 管理后台 (路由、认证、模板)
├── plugins/                # 插件平台 (内置、社区、沙箱)
├── storage/                # 持久化存储 (results.db, admin.db)
├── cache/                  # TTL 缓存层
├── normalizers/            # 数据标准化
├── enrichers/              # 语义标签
├── analyzers/              # 多层分析
├── reporters/              # 输出报告器
├── models/                 # Pydantic 数据模型
├── rules/                  # YAML 规则文件
├── templates/              # Jinja2 模板
├── locales/                # i18n 翻译文件
└── docs/                   # 详细文档
```

## 设计原则

1. **插件是自包含的**：插件负责采集数据并通过稳定的插件契约输出证据。
2. **评分集中在分析器**：所有评分逻辑均在分析器组件中实现。
3. **分析器输出证据**：每个分析器必须为其发现生成证据项。
4. **语义标签驱动**：优先使用 YAML 规则定义语义标签。
5. **容错性**：查询编排必须能够处理部分插件的失效。
6. **报告器无业务逻辑**：报告器仅负责数据展示，不包含业务逻辑。
7. **沙箱化社区插件**：社区插件不得崩溃或危及平台安全。
8. **上下文可选**：上下文分析不应作为强制要求。
9. **批量容错**：批量处理不应因单个条目失败而中断。
10. **敏感配置保护**：严禁在日志中打印 API 密钥等敏感信息。
11. **允许不确定性**：引擎应能处理并输出不确定的分析结果。

## 许可证

开源项目。详见 LICENSE。
