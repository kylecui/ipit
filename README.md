# Threat Intelligence Reasoning Engine

A multi-source threat intelligence analysis and reasoning engine for IP / Domain / URL observables.

## 1. Project Overview

Threat Intelligence Reasoning Engine (TIRE) is not a simple reputation checker.

It is designed to:

- collect threat intelligence from multiple external sources
- normalize heterogeneous results into a unified profile
- identify service semantics such as cloud provider / CDN / Microsoft / Google / email security / scanner infrastructure
- reduce false positives caused by shared infrastructure, anycast, CDN, and major cloud services
- optionally incorporate context such as port, direction, hostname, SNI, and process name
- produce explainable verdicts instead of raw scores only

Typical outputs include:

- Low
- Medium
- High
- Critical
- Inconclusive
- Benign Service
- Internet Noise
- Needs Context

---

## Development Status

### Completed Sprints

- **Sprint 0**: ✅ Project initialization - directory structure, requirements.txt, .env.example, basic config.py
- **Sprint 1**: ✅ Core models and basic runtime framework - all Pydantic models, service/query engine skeletons, unit tests
- **Sprint 2**: ✅ External intelligence collectors MVP - base collector class, AbuseIPDB/OTX/GreyNoise/RDAP/Reverse DNS collectors, concurrent aggregation
- **Sprint 3**: ✅ Standardization and semantic recognition - IPNormalizer, ServiceCatalogEnricher, SemanticEnricher
- **Sprint 4**: ✅ Reputation/Verdict engines - ReputationEngine, VerdictEngine with evidence-based analysis
- **Sprint 5**: ✅ CLI/API/Reporter MVP - JSON/Markdown/CLI reporters, Typer CLI, FastAPI API, full pipeline integration

### MVP Status: ✅ COMPLETE

All Sprint 0-5 completed. The system now provides:
- IP analysis with multi-source intelligence collection
- Semantic service identification and false-positive reduction  
- Reputation scoring with explainable evidence
- CLI/API interfaces with multiple output formats
- End-to-end analysis pipeline from collection to verdict

---

### 2.1 Multi-source threat intelligence collection
Supported sources in MVP:

- AbuseIPDB
- AlienVault OTX
- GreyNoise
- RDAP
- Reverse DNS

Planned extensions:

- VirusTotal
- Shodan
- Censys
- Passive DNS
- Internal telemetry
- Honeynet data
- Flow logs
- EDR context

### 2.2 Semantic service identification
The engine identifies infrastructure types such as:

- cloud provider
- CDN
- Microsoft service
- Google service
- email security service
- internet scanner
- shared infrastructure

This is critical for false-positive reduction.

### 2.3 Explainable verdicts
The engine does not only return a score.  
It also returns:

- evidence items
- score adjustments
- semantic tags
- conflict notes
- recommended actions

### 2.4 Context-aware analysis
When context is available, the engine can adjust verdicts based on:

- direction
- port
- protocol
- hostname
- SNI
- process name
- host role

---

## 3. Architecture

```text
CLI / API / Batch
        |
        v
 Query Orchestration
        |
        v
Collectors -> Normalizers -> Enrichers -> Analyzers -> Verdict -> Reporters
````

Main pipeline:

1. Collect threat intelligence
2. Normalize to standard profile
3. Enrich with semantic tags
4. Analyze reputation
5. Optionally analyze context
6. Resolve conflicts
7. Produce verdict
8. Generate report

---

## 4. Project Structure

```text
threat-intel-reasoning-engine/
├── app/
│   ├── main.py
│   ├── api.py
│   ├── config.py
│   ├── query_engine.py
│   └── service.py
├── models/
│   ├── observable.py
│   ├── ip_profile.py
│   ├── domain_profile.py
│   ├── context_profile.py
│   ├── evidence.py
│   └── verdict.py
├── collectors/
│   ├── base.py
│   ├── abuseipdb.py
│   ├── otx.py
│   ├── greynoise.py
│   ├── rdap.py
│   ├── reverse_dns.py
│   ├── virustotal.py
│   └── shodan.py
├── normalizers/
│   ├── ip_normalizer.py
│   └── domain_normalizer.py
├── enrichers/
│   ├── semantic_enricher.py
│   ├── service_catalog_enricher.py
│   ├── noise_enricher.py
│   └── relationship_enricher.py
├── analyzers/
│   ├── reputation_engine.py
│   ├── semantic_risk_engine.py
│   ├── noise_engine.py
│   ├── contextual_risk_engine.py
│   ├── conflict_resolver.py
│   └── verdict_engine.py
├── graph/
│   ├── entity_graph.py
│   └── correlator.py
├── rules/
│   ├── service_catalog.yaml
│   ├── scoring_rules.yaml
│   ├── noise_rules.yaml
│   └── action_rules.yaml
├── reporters/
│   ├── json_reporter.py
│   ├── markdown_reporter.py
│   ├── html_reporter.py
│   └── cli_reporter.py
├── adapters/
│   ├── siem_adapter.py
│   ├── soar_adapter.py
│   └── csv_adapter.py
├── cache/
│   ├── cache_store.py
│   └── ttl_cache.py
├── storage/
│   ├── sqlite_store.py
│   └── file_store.py
├── templates/
│   ├── report.md.j2
│   └── report.html.j2
├── tests/
├── docs/
├── requirements.txt
├── README.md
└── .env.example
```

---

## 5. Installation

### 5.1 Create virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 5.2 Install dependencies

```bash
pip install -r requirements.txt
```

---

## 6. Configuration

Create a `.env` file based on `.env.example`.

Example:

```env
ABUSEIPDB_API_KEY=
OTX_API_KEY=
GREYNOISE_API_KEY=
VT_API_KEY=
SHODAN_API_KEY=

CACHE_TTL_HOURS=24
HTTP_TIMEOUT_SECONDS=15
MAX_RETRIES=2
LOG_LEVEL=INFO
```

Notes:

* The application must still work even if some API keys are missing
* Missing collectors should degrade gracefully
* No API key should ever be printed in logs

---

## 7. Running the CLI

### 7.1 Basic IP lookup

```bash
python -m app.main lookup ip 8.8.8.8
```

### 7.2 Generate Markdown report

```bash
python -m app.main report ip 52.123.129.14 --format md
```

### 7.3 Generate JSON report

```bash
python -m app.main report ip 52.123.129.14 --format json
```

### 7.4 Context-aware analysis

```bash
python -m app.main analyze ip 52.123.129.14 --direction outbound --port 443 --hostname ecs.office.com --process MsMpEng.exe
```

### 7.5 Batch analysis

```bash
python -m app.main batch input.csv --format json
```

---

## 8. Running the API

Start the API server:

```bash
uvicorn app.api:app --reload
```

OpenAPI docs:

```text
http://127.0.0.1:8000/docs
```

### 8.1 Health check

```http
GET /healthz
```

### 8.2 IP analysis

```http
GET /api/v1/ip/8.8.8.8
```

### 8.3 Context-aware IP analysis

```http
POST /api/v1/analyze/ip
Content-Type: application/json
```

Body example:

```json
{
  "ip": "52.123.129.14",
  "context": {
    "direction": "outbound",
    "protocol": "tcp",
    "port": 443,
    "hostname": "ecs.office.com",
    "sni": "ecs.office.com",
    "process_name": "MsMpEng.exe",
    "host_role": "workstation"
  }
}
```

---

## 9. Design Rules

The following engineering constraints are mandatory:

1. Collectors must not implement final scoring logic
2. All scoring must happen in analyzers
3. All analyzers must emit evidence items
4. Semantic tags should be driven by YAML rules when possible
5. Query orchestration must tolerate partial collector failures
6. Reporters must not contain business logic
7. Context analysis must be optional
8. Batch analysis must be item-fault-tolerant
9. Sensitive configuration must never be printed
10. The engine must allow inconclusive outputs

---

## 10. Supported Verdict Types

Primary verdict levels:

* Low
* Medium
* High
* Critical
* Inconclusive

Additional semantic decision states may include:

* Benign Service
* Internet Noise
* Needs Context

---

## 11. Example Expected Outcomes

### Case 1: 8.8.8.8

Expected:

* organization: Google
* tags: cloud_provider, google_service
* verdict: Low

### Case 2: 1.1.1.1

Expected:

* organization: Cloudflare
* tags: cloud_provider, cdn
* verdict: Low

### Case 3: 52.123.129.14

Expected:

* organization: Microsoft
* tags: cloud_provider, microsoft_service, shared_infrastructure
* verdict: Low or Inconclusive-low depending on evidence mix

### Case 4: Known malicious public IOC

Expected:

* high reputation score
* High or Critical verdict

### Case 5: GreyNoise benign scanner

Expected:

* noise tags
* not automatically classified as critical malicious infrastructure

---

## 12. Testing

Run tests:

```bash
pytest -q
```

Recommended test categories:

* model validation
* collector parsing
* normalizer output
* semantic tagging
* reputation scoring
* verdict generation
* API endpoint testing
* CLI smoke tests
* end-to-end mock pipeline tests

---

## 13. MVP Definition of Done

The MVP is considered complete when the following are implemented:

* IP lookup
* AbuseIPDB / OTX / GreyNoise / RDAP / Reverse DNS collectors
* IPProfile normalization
* service catalog enrichment
* reputation engine
* verdict engine
* JSON / Markdown / CLI outputs
* CLI commands
* FastAPI endpoint
* basic tests

---

## 14. Roadmap

### Phase 1

* MVP collectors
* semantic service identification
* reputation engine
* CLI / API / Markdown report

### Phase 2

* VirusTotal
* Shodan
* rule externalization
* batch analysis
* HTML reports

### Phase 3

* contextual risk engine
* internal telemetry integration
* honeynet input
* conflict resolver

### Phase 4

* graph correlation
* dashboard
* SIEM/SOAR adapters
* production observability

---

## 15. License / Notes

This project is intended for defensive security analysis, SOC triage, threat hunting support, and explainable threat intelligence reasoning.

It should not be implemented as a single-source blacklist lookup tool.
Its core value lies in:

* multi-source intelligence fusion
* semantic false-positive reduction
* context-aware risk reasoning
* explainable evidence-driven verdicts

