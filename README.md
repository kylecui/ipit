# TIRE — Threat Intelligence Reasoning Engine

A multi-source threat intelligence analysis and reasoning engine for IP observables, featuring evidence-driven verdicts, semantic service recognition, and LLM-enhanced narrative reports.

> **Note**: 中文文档请参阅下文。 (Chinese documentation is available below.)

## Key Features

- **9 Intelligence Sources**: AbuseIPDB, AlienVault OTX, GreyNoise, VirusTotal (including passive DNS/resolutions), Shodan, RDAP, Reverse DNS, Honeynet, and Internal Flow.
- **Plugin-based Analysis Pipeline**: A structured flow from Plugins → Enrichers → Analyzers → Verdict → Reporters.
- **Semantic Service Recognition**: YAML-driven service catalog identifies cloud providers, CDNs, and Microsoft/Google services to reduce false positives.
- **Evidence-driven Verdicts**: Every verdict includes scored evidence items with detailed explanations, ensuring transparency beyond simple numbers.
- **Scoring System**: A 0–100 scale where higher values indicate greater danger. Thresholds: Low (0–20), Medium (21–45), High (46–75), and Critical (76–100).
- **LLM-enhanced Narrative Reports**: On-demand AI-generated threat intelligence reports with contextual analysis, powered by OpenAI-compatible APIs. Includes AI/Template badges.
- **Domain Correlation**: Combines rDNS domain extraction with VirusTotal passive DNS resolutions for comprehensive infrastructure mapping.
- **Bilingual i18n (EN/ZH)**: Full internationalization support for the Web UI, CLI output, and reports. Includes a language switcher in the web interface.
- **4 Input Modes**: Supports CLI commands, REST API, Web Dashboard, and CSV Batch processing.
- **5 Output Formats**: Rich CLI (via `rich`), JSON, Markdown, HTML fragments, and Narrative HTML reports.
- **Docker Deployment**: Production-ready Docker Compose setup with health checks and persistent SQLite volumes for cache and admin data.
- **Open Plugin Platform**: Builtin and community plugins can be added without modifying core platform code.
- **Sandboxed Community Plugins**: Untrusted/community plugins run in isolated subprocesses to protect platform stability and secrets.
- **Context-aware Analysis**: Optional context (port, direction, hostname, process) for enhanced verdict accuracy.
- **Externalized Rules**: YAML configuration files for scoring rules, action rules, and the service catalog—no code changes required for tuning.
- **Fault-tolerant**: Graceful degradation ensures the system remains functional even when individual collectors fail.
- **SQLite Caching**: Configurable TTL-based caching for API responses to improve performance and reduce API quota usage.

## Architecture Overview

```
Input Layer (CLI / API / Web UI / Batch)
         ↓
  Query Orchestration (QueryEngine)
         ↓
Plugins → Enrichers → Analyzers → Verdict → Reporters
   ↑           ↑            ↑          ↑         ↑
Dynamic    Semantic    Multi-layer  Evidence  Multi-format
Sources    Tags        Analysis     Fusion    Output
```

### Deployment Architecture

```
User Browser / API Client
         │
         ▼
┌──────────────────┐
│   TIRE :8000     │  FastAPI + Uvicorn
│                  │  Web UI + REST API + Health checks
└────────┬─────────┘
         │
         ├──────────────► SQLite Cache (Docker Volume)
         │
         └──────────────► Admin DB (Docker Volume)
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
# Edit .env with your API keys

# Run CLI
uv run python -m app.main lookup 8.8.8.8

# Start Web UI
uv run uvicorn app.api:app --reload
# Open http://127.0.0.1:8000/
```

### Docker Deployment (Recommended for Production)

```bash
cp .env.example .env
# Edit .env with your API keys
docker compose up -d
# Open http://localhost:8000/ (direct app) or the configured reverse-proxy host
```

### Production Access Model

The current primary deployment model is:

- TIRE V2 is served at `/` (root path)
- the public host is `tire.rswitch.dev`
- non-target Host headers should be rejected by the reverse proxy

If you deploy behind a reverse proxy, the expected public entrypoint is:

```text
https://tire.rswitch.dev/
```

## Usage

### CLI Commands

TIRE provides four primary commands, all supporting `--format` (json/md/cli), `--lang` (en/zh), and `--refresh` (to bypass cache).

- `lookup`: Quick IP lookup.
  ```bash
  uv run python -m app.main lookup 1.1.1.1 --format cli
  ```
- `report`: Generate a detailed report.
  ```bash
  uv run python -m app.main report 8.8.8.8 --format md --output report.md
  ```
- `analyze`: Contextual analysis.
  ```bash
  uv run python -m app.main analyze 192.168.1.1 --direction outbound --port 443
  ```
- `batch`: Process multiple observables from a CSV file.
  ```bash
  uv run python -m app.main batch ips.csv --format json
  ```

### REST API Endpoints

- `GET  /healthz` — Health check.
- `GET  /readyz` — Readiness check.
- `GET  /api/v1/ip/{ip}` — Quick IP lookup.
- `POST /api/v1/analyze/ip` — Contextual analysis.
- `GET  /api/v1/debug/sources/{ip}` — Debug raw source data.
- `POST /api/v1/report/generate` — Generate narrative report.
- `GET  /` — Web dashboard.
- `POST /analyze` — Web form submission.

Example lookup with curl:
```bash
curl http://localhost:8000/api/v1/ip/8.8.8.8
```

When deployed behind the production host restriction, use:

```bash
curl https://tire.rswitch.dev/api/v1/ip/8.8.8.8
```

### Web Dashboard

Access the dashboard at `http://localhost:8000/`. Enter an IP address and click **Analyze** to see color-coded results with evidence. Click **Generate Report** for an AI-powered narrative report. Use the language switcher in the navbar to toggle between English and Chinese.

In the current root-path deployment model, the public dashboard entrypoint is `https://tire.rswitch.dev/`.

## Configuration

### Environment Variables

Grouped by category in `.env`:

**Admin Portal**
- `ADMIN_PASSWORD`: Controls the bootstrap/default admin password for the admin portal. Set this in `.env` and keep it out of version-controlled documentation.

**API Keys**
- `ABUSEIPDB_API_KEY`: API key for AbuseIPDB.
- `OTX_API_KEY`: API key for AlienVault OTX.
- `GREYNOISE_API_KEY`: API key for GreyNoise.
- `VT_API_KEY`: API key for VirusTotal.
- `SHODAN_API_KEY`: API key for Shodan.

**Performance**
- `CACHE_TTL_HOURS`: Cache duration (default: 24).
- `HTTP_TIMEOUT_SECONDS`: Request timeout (default: 15).
- `MAX_RETRIES`: Number of retries for failed requests (default: 2).

**Application**
- `LOG_LEVEL`: Logging level (default: INFO).
- `LANGUAGE`: Default system language (default: en).
- `TIRE_PORT`: Port for the application (default: 8000).

**LLM (for narrative reports)**
- `LLM_API_KEY`: API key for the LLM provider.
- `LLM_MODEL`: Model name (default: gpt-4o).
- `LLM_BASE_URL`: API base URL (default: https://api.openai.com/v1).

### Rule Files

- `rules/scoring_rules.yaml`: Reputation scoring weights and thresholds.
- `rules/action_rules.yaml`: Recommended action mappings based on verdicts.
- `rules/service_catalog.yaml`: Known service identification patterns.

## Project Structure

```
├── app/                    # Application core
│   ├── api.py              # FastAPI routes + Web UI
│   ├── main.py             # CLI entry point (Typer)
│   ├── config.py           # Pydantic settings
│   ├── i18n.py             # Internationalization
│   ├── query_engine.py     # Pipeline orchestration
│   └── llm_client.py       # LLM API client
├── plugins/                # Plugin platform
│   ├── base.py             # TIPlugin ABC + PluginResult
│   ├── registry.py         # Discovery + registration
│   ├── sandbox.py          # Subprocess sandbox runner
│   ├── builtin/            # Trusted built-in plugins
│   └── community/          # Community/demo plugins
├── normalizers/            # Data standardization
├── enrichers/              # Semantic tagging
├── analyzers/              # Multi-layer analysis
│   ├── reputation_engine.py
│   └── verdict.py          # Evidence fusion + final verdict
├── reporters/              # Output formatters
│   ├── narrative_reporter.py  # LLM narrative reports
│   └── json, markdown, cli, html reporters
├── models/                 # Pydantic data models
├── rules/                  # YAML rule files
├── templates/              # Jinja2 HTML templates
├── locales/                # i18n translation files (en.json, zh.json)
├── docker-compose.yml
├── Dockerfile
├── nginx/nginx.conf
└── requirements.txt
```

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

## Testing

```bash
uv run pytest
```

## Roadmap

v2.0 introduced the plugin architecture with sandboxed execution — see `docs/V2_PLUGIN_ARCHITECTURE.md`.

## License

Open source. See LICENSE for details.

---

# TIRE — 威胁情报推理引擎

多源威胁情报分析与推理引擎，支持证据驱动的判决、语义服务识别以及 LLM 增强的叙述性报告。

## 核心功能

- **9 个情报源**：AbuseIPDB, AlienVault OTX, GreyNoise, VirusTotal (含 passive DNS), Shodan, RDAP, Reverse DNS, Honeynet, Internal Flow。
- **多层分析流水线**：收集器 → 标准化器 → 丰富器 → 分析器 → 判决 → 报告器。
- **语义服务识别**：基于 YAML 的服务目录，识别云厂商、CDN 及 Microsoft/Google 服务，减少误报。
- **证据驱动判决**：每个判决均包含带分数的证据项及详细说明，而非单一数字。
- **评分系统**：0–100 分制。阈值：低 (0–20), 中 (21–45), 高 (46–75), 严重 (76–100)。
- **LLM 增强报告**：按需生成 AI 威胁情报报告，支持上下文分析，由 OpenAI 兼容 API 驱动。
- **域名关联**：结合 rDNS 提取与 VirusTotal passive DNS 解析，进行基础设施映射。
- **双语支持 (EN/ZH)**：Web UI、CLI 输出及报告全面支持中英文切换。
- **4 种输入模式**：CLI、REST API、Web 仪表板、CSV 批量处理。
- **5 种输出格式**：Rich CLI, JSON, Markdown, HTML 片段, 叙述性 HTML 报告。
- **Docker 部署**：生产就绪的 Docker Compose 配置，含 Nginx 反向代理与健康检查。
- **上下文感知**：支持端口、方向、主机名、进程等可选上下文，提升判决准确度。
- **规则外部化**：通过 YAML 配置评分规则、行动规则和服务目录，无需修改代码。
- **容错机制**：单个收集器失败时保持系统整体可用。
- **SQLite 缓存**：基于 TTL 的缓存机制，提升性能并节省 API 配额。

## 快速开始

### 本地开发
```bash
git clone <repository-url>
cd ipit
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
cp .env.example .env
uv run python -m app.main lookup 8.8.8.8
```

### Docker 部署
```bash
docker compose up -d
```

## 设计原则

1. **收集器不评分**：收集器仅负责数据采集。
2. **评分集中在分析器**：所有评分逻辑均在分析器中实现。
3. **分析器输出证据**：每个分析结果必须附带证据项。
4. **语义标签驱动**：优先使用 YAML 规则定义语义标签。
5. **容错性**：查询引擎必须能够处理部分收集器的失效。
6. **报告器无业务逻辑**：报告器仅负责数据展示。
7. **上下文可选**：上下文分析不应作为强制要求。
8. **批量容错**：批量处理不应因单个条目失败而中断。
9. **敏感配置保护**：严禁在日志中打印 API 密钥等敏感信息。
10. **允许不确定性**：引擎应能处理并输出不确定的分析结果。
