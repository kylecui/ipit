# TIRE V2 Development Principles

> This document defines binding development principles for TIRE V2.
> All contributors (human and AI) **must** follow these rules.

## Branch & Deployment

- **Development branch**: `dev` — all V2 work happens here.
- **Production V1**: served at `/` (root path). Must never be affected by V2 changes.
- **Production V2**: served at `/v2` (sub-path via `ROOT_PATH=/v2`).
- **Test server**: `ssh root@45.136.13.56` — runs both V1 and V2 simultaneously.
- **Golden rule**: V2 development and testing must **never** break V1.

## Project Maturity

TIRE is no longer an internal test project. The "keep it simple" / "越简单越好" philosophy **no longer applies**.

We follow the standards of a conventional GitHub open-source project:

- Meaningful commit messages (conventional commits preferred).
- Comprehensive documentation (README, inline docstrings, architecture docs).
- Test coverage for new features.
- Proper error handling — no bare `except:` or `catch(e) {}`.
- Type annotations on all new Python code.
- i18n keys for all user-facing strings (EN + ZH).
- No secrets in code or logs.

## Architecture Principles

1. **Plugins are self-contained**: Each plugin handles collection, normalization, AND scoring.
2. **All scoring in Analyzers**: Scoring logic is centralized within analyzer components.
3. **Analyzers emit evidence**: Every analyzer must produce `EvidenceItem`s for its findings.
4. **Semantic tag driven**: Use YAML rules to drive semantic tagging.
5. **Fault tolerance**: The query engine must tolerate failures from individual plugins.
6. **Reporters have no business logic**: Reporters are presentation-only.
7. **Sandbox untrusted plugins**: Community plugins run in isolated subprocesses.
8. **Optional context**: Contextual analysis is always optional.
9. **Batch fault tolerance**: Batch processing must survive individual item failures.
10. **No sensitive config in logs**: Never print API keys or secrets in logs.
11. **Allow inconclusive output**: The engine must handle uncertain results.

## V2 Feature Principles

### API Key Management
- **No more env-only API keys**. Users configure their own plugin API keys and LLM keys through the admin UI.
- **Hybrid mode**: Admin sets shared default keys; users can override with personal keys.
- Admin controls whether users may use the shared (admin-configured) keys.
- **Fallback chain**: `user_key → shared_admin_key → env_var → None`.
- Backward compatibility: `.env` API keys remain as the final fallback.
- API keys are encrypted at rest (Fernet).

### Persistence & Caching
- Query results are **persistently stored** (not just TTL-cached).
- On refresh, old results are **archived** (not overwritten) to enable historical comparison.
- Results older than the staleness threshold (default: 7 days) trigger re-query even if persisted.
- **Per-API-key sharing**: queries using shared (admin) API keys can be shared across users; queries using personal keys are isolated to that user.
- Persistence DB: `storage/results.db` (separate from `cache/cache.db`).

### Reports
- **Report generation never triggers new data queries**. All data must be collected during the analysis phase.
- Generated reports include **query date** and **report generation timestamp**.
- Reports older than the staleness threshold carry a **staleness warning banner**.
- AI-generated reports include an **AIGC disclaimer**.
- Duplicate report requests serve from cache (per-user, since LLM settings differ). Users must explicitly request regeneration to invoke the LLM again.
- Reports are persistently stored for historical comparison.

### Comparison
- Support **timeline view**: score changes across multiple queries of the same IP.
- Support **side-by-side diff**: detailed comparison between two query snapshots or two reports.

### New TI Plugins
- **ThreatBook (微步在线)**: `plugins/builtin/threatbook.py` — uses `https://api.threatbook.cn/v3` API.
- **TianJi YouMeng (天际友盟)**: `plugins/builtin/tianjiyoumeng.py` — uses RedQueen platform API. Enterprise-only (no free tier).
- New plugins follow the existing `TIPlugin` ABC contract exactly.

## Code Conventions

### Python
- Python 3.11+ features are allowed.
- Type hints on all function signatures.
- Docstrings on all public classes and methods.
- `logging` module for all output — never `print()`.
- Raw `sqlite3` with WAL mode for database access (following existing pattern).
- Pydantic models for data contracts.
- `httpx.AsyncClient` for HTTP requests.

### Frontend
- Bootstrap 5 for UI components.
- Jinja2 templates (`.html.j2`).
- All user-facing strings via i18n (`locales/en.json`, `locales/zh.json`).
- No external JS frameworks beyond what's already in use.

### Testing
- `pytest` + `pytest-asyncio` for async tests.
- Tests must not call real external APIs (mock/fixture all HTTP).
- Test files mirror source structure: `tests/test_<module>.py`.

## File Layout Reference

```
AGENTS.md                    ← This file
app/                         ← Application core (config, API, engine)
plugins/                     ← Plugin platform (base, registry, sandbox, builtin/, community/)
storage/                     ← Persistence (sqlite_store, result_store)
cache/                       ← TTL cache layer
admin/                       ← Admin portal (DB, routes, auth, templates)
reporters/                   ← Output formatters (narrative, HTML, JSON, MD, CLI)
models/                      ← Pydantic data models
analyzers/                   ← Scoring & verdict engines
enrichers/                   ← Semantic enrichment
normalizers/                 ← Data standardization
rules/                       ← YAML rule files
config/                      ← Plugin & app configuration
templates/                   ← Jinja2 HTML templates
locales/                     ← i18n translation files
tests/                       ← Test suite
docs/                        ← Extended documentation
```
