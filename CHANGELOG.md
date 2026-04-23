# Changelog

All notable changes to TIRE are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.5.0] — 2026-04-23

### Added

**V2 Plugin Architecture**
- Migrated 9 legacy collectors to self-contained `TIPlugin` ABC with unified `collect → normalize → score` contract.
- New plugin: ThreatBook (微步在线) — `plugins/builtin/threatbook.py`.
- New plugin: TianJi YouMeng (天际友盟) — `plugins/builtin/tianjiyoumeng.py`.
- Dynamic plugin registry with YAML-driven configuration (`config/plugins.yaml`).
- Community plugin platform with sandboxed subprocess execution.
- Plugin upload, validation, enable/disable via admin portal.

**Admin Portal**
- Full admin dashboard at `/admin/` with authentication and session management.
- User management: create, edit, delete users with role-based access.
- Policy groups: configurable permission groups controlling shared key access and feature availability.
- Plugin management: enable/disable plugins, configure per-plugin API keys.
- Shared API key management with Fernet encryption at rest.
- Shared and personal LLM configuration management.
- API usage statistics dashboard (plugin calls and LLM token usage).
- Real-time log viewer via Server-Sent Events (SSE).
- Audit logging for administrative actions.

**Persistent Result Storage**
- Query results stored as immutable snapshots in `storage/results.db`.
- Old results archived on refresh (not overwritten), enabling historical comparison.
- Staleness threshold (default: 7 days) triggers automatic re-query.
- Per-API-key result sharing: shared-key queries visible to all; personal-key queries isolated.

**Historical Comparison**
- Timeline view: score changes across multiple queries of the same IP.
- Side-by-side snapshot diff between any two query snapshots.
- Report comparison between any two generated reports.
- Personal snapshot and report history endpoints (`/api/v1/me/snapshots`, `/api/v1/me/reports`).

**Report Enhancements**
- Report caching with per-user isolation (LLM settings differ per user).
- Explicit regeneration required to re-invoke LLM (no silent re-generation).
- Reports include query date and generation timestamp.
- Stale reports display a staleness warning banner.
- AI-generated reports include an AIGC disclaimer.
- Template fallback when LLM is unavailable.

**API Key Management**
- Hybrid key model: admin sets shared defaults; users can override with personal keys.
- Fallback chain: `user_key → shared_admin_key → env_var → None`.
- Admin policy controls whether users may consume shared keys.
- All keys encrypted at rest using Fernet symmetric encryption.

**Deployment**
- Sub-path deployment support via `ROOT_PATH` environment variable.
- `nginx/nginx.conf.example` provided (no hardcoded hostnames or cert paths).
- Docker volume mapping updated: `admin.db` moved to `data/` to avoid shadowing code directory.

**Documentation**
- Comprehensive V2 documentation set: Quick Start, Deployment, Configuration, Admin Guide, Troubleshooting.
- Bilingual README rewritten for V2 feature set.
- Software copyright user manual (软著用户手册) with document index.

### Changed
- Analysis pipeline restructured: Plugins → Enrichers → Analyzers → Verdict → Reporters.
- Result storage separated from TTL cache (`storage/results.db` vs `cache/cache.db`).
- Admin database relocated from `admin/admin.db` to `data/admin.db` to prevent Docker volume conflicts.

### Fixed
- Docker volume shadowing `admin/` code directory when mounting `admin.db`.

---

## [1.0.0] — 2026-03-11

### Added

**Intelligence Sources**
- AbuseIPDB collector — abuse reports, confidence scoring
- AlienVault OTX collector — pulse-based threat data
- GreyNoise collector — internet noise classification
- VirusTotal collector — malware detection ratios + passive DNS resolutions
- Shodan collector — open ports, services, banners
- RDAP collector — IP registration and ownership data
- Reverse DNS collector — PTR record resolution
- Honeynet collector — honeypot activity data
- Internal Flow collector — internal network telemetry

**Analysis Pipeline**
- Multi-layer analysis: reputation, noise, context, internal telemetry
- Evidence-driven verdict engine with scored evidence items
- Reputation scoring: 0–100 scale with configurable thresholds (Low/Medium/High/Critical)
- Semantic service recognition via YAML service catalog (cloud providers, CDNs, etc.)
- IP normalization and data standardization
- Entity graph correlation for infrastructure relationships
- Domain correlation combining rDNS + VirusTotal passive DNS

**Reporting**
- JSON reporter
- Markdown reporter
- Rich CLI reporter (colored terminal output via `rich`)
- HTML fragment reporter for web embedding
- LLM-enhanced narrative report generation (OpenAI-compatible API)
- AI vs Template badge on narrative reports
- On-demand report generation (Generate Report button)

**Interfaces**
- CLI with 4 commands: lookup, report, analyze, batch
- REST API (FastAPI) with health checks, IP analysis, debug endpoints
- Web dashboard with Bootstrap-styled analysis results
- CSV batch processing mode
- Context-aware analysis (port, direction, hostname, process)

**Internationalization**
- Full bilingual support (English / Chinese)
- Translation system with JSON locale files (121 keys each)
- Language switcher in web UI navbar
- CLI --lang flag for output language selection
- All reporters support language parameter

**Infrastructure**
- Docker deployment with Dockerfile and docker-compose.yml
- Nginx reverse proxy with security headers
- SQLite caching with configurable TTL
- Pydantic-based configuration via environment variables
- Externalized YAML rule files (scoring, actions, service catalog)
- Structured logging with configurable log levels
- Debug endpoint for raw source data inspection
- Health check (GET /healthz) and readiness check (GET /readyz)

### Fixed
- Docker: switched from Snap to APT Docker for compatibility
- Dockerfile: added missing enrichers/ and graph/ directories
- Added python-multipart dependency for form data handling
- AbuseIPDB confidence field name mismatch (abuse_confidence_score)
- VirusTotal, Honeynet, Internal Flow not wired into reputation engine
- i18n: locale file loading in Docker container
- i18n: 405 error on language switch (GET vs POST)
- Score display clarity with color-coded /100 format
- Language switcher losing analysis results on switch
- RDAP entities rendering as raw JSON dicts instead of human-readable strings

---

## [0.1.0] — Initial Development

### Added
- Project initialization and directory structure
- Core Pydantic models (Observable, IPProfile, DomainProfile, etc.)
- Base collector abstract class with error handling
- Query engine pipeline orchestration
- Basic configuration via .env
