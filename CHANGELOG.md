# Changelog

All notable changes to TIRE are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
