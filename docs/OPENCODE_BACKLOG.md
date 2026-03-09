# Threat Intelligence Reasoning Engine
## OpenCode Implementation Backlog

Version: 2.1  
Date: 2026-03-09  
Audience: OpenCode / AI Coding Agent / Security Engineering Team

---

# 1. Backlog 使用说明

本 Backlog 供 OpenCode 按阶段自动开发使用。

执行原则：

1. 按 Sprint 顺序实现
2. 每个 Sprint 完成后必须可运行、可测试
3. 不允许跨 Sprint 大量预埋未完成逻辑
4. 所有模块都必须可单元测试
5. 所有 Collector 必须支持错误降级
6. 所有 Engine 必须输出 evidence
7. 规则必须逐步外置到 YAML
8. 报告模板与业务逻辑分离

---

# 2. 开发优先级

优先级定义：

- **P0** = 必须优先完成，MVP 核心路径
- **P1** = 建议在 MVP 后尽快完成
- **P2** = 增强功能
- **P3** = 平台化/高级扩展

---

# 3. Sprint 总览

| Sprint | 目标 | 优先级 |
|---|---|---|
| Sprint 0 | 项目初始化与基础骨架 | P0 |
| Sprint 1 | 核心模型与基础运行框架 | P0 |
| Sprint 2 | 外部情报采集器 MVP | P0 |
| Sprint 3 | 标准化与语义识别 | P0 |
| Sprint 4 | Reputation / Verdict 引擎 | P0 |
| Sprint 5 | CLI / API / Reporter MVP | P0 |
| Sprint 6 | Cache / Rule Config / Batch | P1 |
| Sprint 7 | VirusTotal / Shodan / Noise Engine | P1 |
| Sprint 8 | Contextual Risk Engine | P1 |
| Sprint 9 | Internal Telemetry Integration | P2 |
| Sprint 10 | Graph Correlation Engine | P2 |
| Sprint 11 | Web UI / HTML / Dashboard | P2 |
| Sprint 12 | Production Hardening / Observability | P1 |

---

# 4. Sprint 0：项目初始化与基础骨架

## Epic S0-E1：仓库初始化

### TASK S0-E1-T1
**目标：** 初始化 Python 项目目录  
**优先级：** P0

### 输出文件
```text
threat-intel-reasoning-engine/
├── app/
├── models/
├── collectors/
├── normalizers/
├── enrichers/
├── analyzers/
├── graph/
├── reporters/
├── adapters/
├── rules/
├── cache/
├── storage/
├── templates/
├── tests/
├── docs/
├── requirements.txt
├── README.md
└── .env.example
````

### 验收标准

* 目录结构完整
* `python -m pip install -r requirements.txt` 成功
* 仓库可直接打开并运行最小入口

---

### TASK S0-E1-T2

**目标：** 写入 `requirements.txt`
**优先级：** P0

### 内容要求

至少包括：

```text
fastapi
uvicorn
httpx
typer
pydantic
jinja2
python-dotenv
rich
pyyaml
pytest
pytest-asyncio
```

### 验收标准

* 所有依赖成功安装
* pytest 能正常启动

---

### TASK S0-E1-T3

**目标：** 提供 `.env.example`
**优先级：** P0

### 内容要求

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

### 验收标准

* 配置项覆盖核心 Collector 和系统参数

---

## Epic S0-E2：基础配置模块

### TASK S0-E2-T1

**目标：** 实现配置加载
**文件：** `app/config.py`
**优先级：** P0

### 要求

* 从环境变量读取配置
* 提供默认值
* 使用 Pydantic Settings 风格或等价实现
* 对缺失 API Key 可容忍，不阻断系统启动

### 验收标准

* `config.py` 可独立 import
* 对未配置 API Key 仅 warning，不报错退出

---

# 5. Sprint 1：核心模型与基础运行框架

## Epic S1-E1：Pydantic 核心模型

### TASK S1-E1-T1

**目标：** 实现 `models/observable.py`
**优先级：** P0

### 模型

```python
class Observable(BaseModel):
    type: str
    value: str
```

### 验收标准

* 支持 `ip/domain/url` 类型
* 非法 type 抛验证错误

---

### TASK S1-E1-T2

**目标：** 实现 `models/ip_profile.py`
**优先级：** P0

### 模型字段

* ip
* version
* asn
* organization
* country
* network
* rdns
* hostnames
* tags
* sources
* external_refs
* timestamps

### 验收标准

* 可序列化为 JSON
* 对默认空列表/字典处理正确

---

### TASK S1-E1-T3

**目标：** 实现 `models/domain_profile.py`
**优先级：** P1

### 验收标准

* 能承载未来 domain 分析信息
* 当前未用字段允许为空

---

### TASK S1-E1-T4

**目标：** 实现 `models/context_profile.py`
**优先级：** P1

### 字段

* direction
* protocol
* port
* hostname
* sni
* process_name
* process_path
* host_role
* timestamp
* src_ip
* dst_ip

### 验收标准

* 字段均为可选
* 可作为 API body 一部分

---

### TASK S1-E1-T5

**目标：** 实现 `models/evidence.py`
**优先级：** P0

### 模型

```python
class EvidenceItem(BaseModel):
    source: str
    category: str
    severity: str
    title: str
    detail: str
    score_delta: int = 0
    confidence: float = 0.0
    raw: dict[str, Any] = {}
```

### 验收标准

* 可供所有 engine 复用
* 能直接输出到 JSON/Markdown

---

### TASK S1-E1-T6

**目标：** 实现 `models/verdict.py`
**优先级：** P0

### 字段

* object_type
* object_value
* reputation_score
* contextual_score
* final_score
* level
* confidence
* decision
* summary
* evidence
* tags

### 验收标准

* 可直接做 API response
* evidence 字段支持 `EvidenceItem[]`

---

## Epic S1-E2：应用服务骨架

### TASK S1-E2-T1

**目标：** 实现 `app/service.py`
**优先级：** P0

### 要求

* 提供统一服务入口类
* 后续由 CLI / API 共用

### 示例接口

```python
class ThreatIntelService:
    async def analyze_ip(self, ip: str, context: ContextProfile | None = None):
        ...
```

### 验收标准

* 能被 CLI 和 API 同时调用
* 不包含具体 Collector 逻辑

---

### TASK S1-E2-T2

**目标：** 实现 `app/query_engine.py` 骨架
**优先级：** P0

### 要求

定义主流程，但先不填满逻辑：

1. collect
2. normalize
3. enrich
4. analyze
5. verdict
6. report

### 验收标准

* 可返回占位结果
* 方法签名稳定

---

# 6. Sprint 2：外部情报采集器 MVP

## Epic S2-E1：Collector 基类

### TASK S2-E1-T1

**目标：** 实现 `collectors/base.py`
**优先级：** P0

### 要求

定义统一接口：

```python
class BaseCollector(ABC):
    name: str

    @abstractmethod
    async def query(self, observable: str) -> dict:
        ...
```

### 额外要求

* 封装超时
* 封装 retry
* 捕获异常并返回统一错误结构

### 验收标准

* 所有后续 Collector 继承它
* collector 出错时不会抛未处理异常到主流程

---

## Epic S2-E2：AbuseIPDB Collector

### TASK S2-E2-T1

**文件：** `collectors/abuseipdb.py`
**优先级：** P0

### 要求

* 调用 `/api/v2/check`
* 支持 `ipAddress`
* 默认 `maxAgeInDays=90`
* 解析：

  * abuseConfidenceScore
  * totalReports
  * countryCode
  * usageType
  * isp
  * domain
  * isWhitelisted

### 统一输出建议

```json
{
  "source": "abuseipdb",
  "ok": true,
  "data": {
    "abuse_confidence_score": 0,
    "total_reports": 0,
    "country_code": "",
    "usage_type": "",
    "isp": "",
    "domain": "",
    "is_whitelisted": false
  },
  "error": null
}
```

### 验收标准

* API key 缺失时 graceful degrade
* HTTP 错误不致系统崩溃
* 解析字段完整

---

## Epic S2-E3：OTX Collector

### TASK S2-E3-T1

**文件：** `collectors/otx.py`
**优先级：** P0

### 要求

调用：

```text
/api/v1/indicators/IPv4/{ip}/general
```

### 解析字段

* pulse_info.count
* reputation
* sections
* related indicators if available
* passive DNS / hostname clues if response包含

### 验收标准

* 成功解析脉冲数与信誉字段
* 对字段缺失有保护

---

## Epic S2-E4：GreyNoise Collector

### TASK S2-E4-T1

**文件：** `collectors/greynoise.py`
**优先级：** P0

### 要求

调用 community lookup
解析：

* noise
* riot
* classification
* name
* link
* last_seen

### 验收标准

* 区分 benign / malicious / unknown / riot
* 输出统一结构

---

## Epic S2-E5：RDAP Collector

### TASK S2-E5-T1

**文件：** `collectors/rdap.py`
**优先级：** P0

### 要求

* 查询 IP RDAP 信息
* 解析 organization / country / handle / network CIDR / entities
* 尽可能提取 ASN；若 RDAP 不能稳定提供 ASN，允许只保留 org/network/country，并在后续扩展 IPinfo/BGPView

### 验收标准

* 对不同 RDAP 返回格式有兼容性
* 至少提取出组织、网络范围、国家

---

## Epic S2-E6：Reverse DNS Collector

### TASK S2-E6-T1

**文件：** `collectors/reverse_dns.py`
**优先级：** P0

### 要求

* 使用标准 Python 方式查询 PTR
* 返回 rdns 列表
* 超时可控

### 验收标准

* 无 PTR 时返回空列表，不报错
* 支持 IPv4

---

## Epic S2-E7：Collector 聚合器

### TASK S2-E7-T1

**文件：** `collectors/__init__.py` 或 `app/query_engine.py` 中 orchestration
**优先级：** P0

### 要求

* 并发运行多个 Collector
* 单个 Collector 出错不影响整体
* 返回按 source 命名的结果字典

### 验收标准

* 任意一个源失败，整体仍有输出
* 多源结果能汇总进入 normalize 阶段

---

# 7. Sprint 3：标准化与语义识别

## Epic S3-E1：IP Normalizer

### TASK S3-E1-T1

**文件：** `normalizers/ip_normalizer.py`
**优先级：** P0

### 输入

* collectors 汇总结果
* observable = ip

### 输出

* `IPProfile`

### 规则

* 优先从 RDAP 提取 org/country/network
* 从 reverse_dns 提取 rdns/hostnames
* 所有原始源结果进入 `sources`
* 自动填入 timestamp

### 验收标准

* 任一 source 缺失时仍能生成 profile
* 标准化字段命名统一

---

## Epic S3-E2：Service Catalog Enricher

### TASK S3-E2-T1

**文件：** `enrichers/service_catalog_enricher.py`
**优先级：** P0

### 依赖文件

`rules/service_catalog.yaml`

### 功能

* 根据 org / asn / rdns / hostname keyword 打标签
* 第一版先支持：

  * Microsoft
  * Google
  * Cloudflare
  * Akamai
  * AWS
  * Azure
  * GCP
  * Proofpoint
  * Mimecast
  * Shodan
  * Censys

### 输出标签示例

* cloud_provider
* cdn
* microsoft_service
* google_service
* email_security
* internet_scanner
* shared_infrastructure

### 验收标准

* 标签外置于 YAML
* 修改 YAML 不需改 Python 代码

---

## Epic S3-E3：Semantic Enricher

### TASK S3-E3-T1

**文件：** `enrichers/semantic_enricher.py`
**优先级：** P0

### 功能

* 读取 `IPProfile`
* 调用 service catalog
* 根据 org / rdns / hostnames 追加 tags

### 验收标准

* `profile.tags` 正确更新
* 能识别微软/谷歌/Cloudflare 等常见大厂资产

---

## Epic S3-E4：Noise Enricher（基础版）

### TASK S3-E4-T1

**文件：** `enrichers/noise_enricher.py`
**优先级：** P1

### 功能

根据 GreyNoise 结果增加：

* internet_noise
* benign_scanner
* riot
* noise_candidate

### 验收标准

* 仅做标签补充，不直接复杂打分
* 不依赖后续高级上下文模块

---

# 8. Sprint 4：Reputation / Verdict 引擎

## Epic S4-E1：Reputation Engine

### TASK S4-E1-T1

**文件：** `analyzers/reputation_engine.py`
**优先级：** P0

### 功能

输入：

* `IPProfile`

输出：

* reputation_score
* evidence list

### 第一版评分规则

* AbuseIPDB > 90: +30
* AbuseIPDB > 70: +20
* OTX pulse count > 0: +20
* GreyNoise malicious: +20
* GreyNoise benign/riot: -15
* cloud_provider: -15
* official_service/microsoft_service/google_service: -25
* shared_infrastructure: -10
* 仅零散社区上报：-10

### 实现要求

* 规则先写死在 Python
* Sprint 6 再外置到 YAML
* 每次加减分都必须生成 `EvidenceItem`

### 验收标准

* score clamp 到 0-100
* evidence 数组完整记录加减分原因

---

## Epic S4-E2：Semantic Risk Engine

### TASK S4-E2-T1

**文件：** `analyzers/semantic_risk_engine.py`
**优先级：** P1

### 功能

* 对共享基础设施、大厂云资产做附加降权
* 生成 caution flags，如：

  * shared_ip_space
  * cloud_shared_frontend
  * anycast_like_infrastructure

### 验收标准

* 不与 reputation engine 重复打分
* 输出可作为 verdict 解释的一部分

---

## Epic S4-E3：Conflict Resolver（基础版）

### TASK S4-E3-T1

**文件：** `analyzers/conflict_resolver.py`
**优先级：** P1

### 功能

识别基础冲突：

* 社区上报高，但资产语义强烈合法
* 恶意证据弱，合法服务证据强
* 结果不够稳定

### 输出

* `conflict_flags`
* `inconclusive_candidate: bool`

### 验收标准

* 至少能识别“微软云资产 + 零散 abuse 上报”这一类冲突

---

## Epic S4-E4：Verdict Engine

### TASK S4-E4-T1

**文件：** `analyzers/verdict_engine.py`
**优先级：** P0

### 输入

* reputation_score
* semantic tags
* conflict flags
* optional contextual score（当前可为 0）

### 输出

* `Verdict`

### 第一版等级

* 0-20 = Low
* 21-45 = Medium
* 46-75 = High
* 76-100 = Critical
* 若 `inconclusive_candidate=True` 且冲突显著，则 `level=Inconclusive`

### decision 字段

* Low -> allow_with_monitoring
* Medium -> investigate
* High -> alert_and_review
* Critical -> contain_or_block
* Inconclusive -> collect_more_context

### 验收标准

* 能输出完整 Verdict
* summary 为自然语言解释，不是只有分数

---

# 9. Sprint 5：CLI / API / Reporter MVP

## Epic S5-E1：JSON Reporter

### TASK S5-E1-T1

**文件：** `reporters/json_reporter.py`
**优先级：** P0

### 功能

* 输出 JSON dict
* 结构化包含 profile + verdict + raw source summary

### 验收标准

* 可直接用于 API response

---

## Epic S5-E2：Markdown Reporter

### TASK S5-E2-T1

**文件：**

* `reporters/markdown_reporter.py`
* `templates/report.md.j2`

**优先级：** P0

### 报告结构

1. Object Summary
2. Ownership / ASN
3. Threat Intel Summary
4. Semantic Tags
5. Evidence
6. Verdict
7. Recommended Action

### 验收标准

* 生成稳定、可读的 Markdown
* 不泄漏 API key/raw secrets

---

## Epic S5-E3：CLI Reporter

### TASK S5-E3-T1

**文件：** `reporters/cli_reporter.py`
**优先级：** P0

### 要求

使用 `rich` 输出：

* 关键字段高亮
* 表格展示 evidence summary
* 最终 verdict 着色

### 验收标准

* CLI 输出清晰，不依赖 Markdown

---

## Epic S5-E4：Typer CLI

### TASK S5-E4-T1

**文件：** `app/main.py`
**优先级：** P0

### 必须实现命令

```bash
tire lookup ip <ip>
tire report ip <ip> --format md
tire report ip <ip> --format json
```

### 可选预埋

```bash
tire analyze ip <ip> --port 443 --direction outbound --hostname ecs.office.com
```

### 验收标准

* `python -m app.main lookup ip 8.8.8.8` 可运行
* report 输出到 stdout 或文件

---

## Epic S5-E5：FastAPI API

### TASK S5-E5-T1

**文件：** `app/api.py`
**优先级：** P0

### 必须实现接口

```http
GET /healthz
GET /api/v1/ip/{ip}
```

### 返回

* JSON report

### 验收标准

* `uvicorn app.api:app --reload` 启动成功
* OpenAPI 文档可见
* `/api/v1/ip/8.8.8.8` 正常返回

---

# 10. Sprint 6：Cache / Rule Config / Batch

## Epic S6-E1：SQLite Cache

### TASK S6-E1-T1

**文件：**

* `cache/cache_store.py`
* `storage/sqlite_store.py`

**优先级：** P1

### 功能

缓存：

* raw collector results
* normalized profile
* verdict

### 默认 TTL

* 24h

### 验收标准

* 同一 IP 重查可命中缓存
* 支持 refresh 跳过缓存

---

## Epic S6-E2：规则外置

### TASK S6-E2-T1

**文件：**

* `rules/scoring_rules.yaml`
* `rules/action_rules.yaml`

**优先级：** P1

### 功能

* 将 reputation score 规则从 Python 提取到 YAML
* 决策 action 外置

### 验收标准

* 修改 YAML 后无需改 Python 逻辑
* 加减分规则可热加载或启动加载

---

## Epic S6-E3：Batch Analyzer

### TASK S6-E3-T1

**文件：**

* `adapters/csv_adapter.py`
* CLI batch command

**优先级：** P1

### 命令

```bash
tire batch input.csv --format json
tire batch input.csv --format md
```

### 输入格式

CSV 至少支持：

```text
type,value
ip,8.8.8.8
ip,1.1.1.1
```

### 验收标准

* 支持批量多 IP 查询
* 错误项不阻断整体批处理

---

# 11. Sprint 7：VirusTotal / Shodan / Noise Engine

## Epic S7-E1：VirusTotal Collector

### TASK S7-E1-T1

**文件：** `collectors/virustotal.py`
**优先级：** P1

### 功能

* 查询 IP object
* 解析：

  * last_analysis_stats
  * reputation
  * as_owner
  * tags
  * related domains if accessible

### 验收标准

* Collector 支持 key 缺失降级
* reputation engine 可读取 VT 结果

---

## Epic S7-E2：Shodan Collector

### TASK S7-E2-T1

**文件：** `collectors/shodan.py`
**优先级：** P1

### 功能

* 查询开放端口
* 提取 banner / service names / certs

### 验收标准

* 仅用于 enrichment，不做重型扫描
* 请求超时、配额控制完善

---

## Epic S7-E3：Noise Engine

### TASK S7-E3-T1

**文件：** `analyzers/noise_engine.py`
**优先级：** P1

### 功能

综合：

* GreyNoise
* service tags
* Shodan scanner signatures
* known measurement infra patterns

### 输出

* noise_score
* noise_classification
* evidence

### 验收标准

* 能区分：

  * internet_noise
  * measurement_traffic
  * common_scanner
  * benign_scanner

---

# 12. Sprint 8：Contextual Risk Engine

## Epic S8-E1：Context API & Model 接入

### TASK S8-E1-T1

**优先级：** P1

### 目标

API 与 CLI 支持输入 ContextProfile：

* direction
* port
* hostname
* sni
* process_name
* host_role

### 验收标准

* CLI / API 都能传上下文
* 未提供 context 时逻辑仍正常

---

## Epic S8-E2：Contextual Risk Engine

### TASK S8-E2-T1

**文件：** `analyzers/contextual_risk_engine.py`
**优先级：** P1

### 第一版规则

* outbound + 443 + microsoft_service + office/ecs -> -20
* outbound + browser/office/defender process -> -15
* inbound + 445/3389/22 + repeated scan -> +25
* suspicious download process (powershell/curl/wget) -> +25
* single short-lived ACK/RST no payload -> -10

### 输出

* contextual_score
* contextual evidence

### 验收标准

* 能和 reputation_score 合并成 final_score
* evidence 解释清晰

---

## Epic S8-E3：增强 Verdict Engine

### TASK S8-E3-T1

**优先级：** P1

### 目标

Verdict Engine 整合：

* reputation_score
* noise_score
* semantic adjustments
* contextual_score
* conflict flags

### 验收标准

* 最终 verdict 更接近真实分析场景
* 能输出 `Benign Service` / `Needs Context` 等附加状态

---

# 13. Sprint 9：Internal Telemetry Integration

## Epic S9-E1：Honeynet Collector

### TASK S9-E1-T1

**文件：** `collectors/honeynet.py`
**优先级：** P2

### 功能

从本地 JSON/CSV/DB 读取蜜网数据：

* hit count
* dst ports
* scan fanout
* time distribution

### 验收标准

* 先支持文件输入，不强依赖线上系统
* 可生成 internal evidence

---

## Epic S9-E2：Internal Flow Collector

### TASK S9-E2-T1

**文件：** `collectors/internal_flow.py`
**优先级：** P2

### 功能

从内部流量样本读取：

* src/dst
* protocol
* ports
* first_seen / last_seen
* bytes/packets
* session count

### 验收标准

* 可接 CSV/JSON
* 能给 Context Engine 供数

---

## Epic S9-E3：Internal Risk Adjustment

### TASK S9-E3-T1

**优先级：** P2

### 功能

结合内部数据做修正：

* 大规模横向扇出 + 高危端口 -> 提升风险
* 只访问微软/谷歌 SaaS 且匹配主机角色 -> 降低风险
* 只命中蜜网节点 -> 明显加权

### 验收标准

* 能体现“内部行为 > 外部声誉”的原则

---

# 14. Sprint 10：Graph Correlation Engine

## Epic S10-E1：Entity Graph 基础版

### TASK S10-E1-T1

**文件：** `graph/entity_graph.py`
**优先级：** P2

### 功能

维护基础节点/边：

* IP
* Domain
* ASN
* Hostname
* Event

### 验收标准

* 支持内存图结构
* 支持添加关系和查询邻居

---

## Epic S10-E2：Correlator

### TASK S10-E2-T1

**文件：** `graph/correlator.py`
**优先级：** P2

### 功能

建立关系：

* IP -> Domain
* IP -> ASN
* Domain -> Resolved IP
* IP -> Internal Host
* Event -> IOC

### 验收标准

* 可为报告补充关系摘要
* 为后续 Neo4j 扩展预留接口

---

# 15. Sprint 11：Web UI / HTML / Dashboard

## Epic S11-E1：HTML Reporter

### TASK S11-E1-T1

**文件：**

* `reporters/html_reporter.py`
* `templates/report.html.j2`

**优先级：** P2

### 功能

生成可读 HTML 报告。

### 验收标准

* 能离线保存打开
* 支持 evidence table / score summary

---

## Epic S11-E2：基础 Web UI

### TASK S11-E2-T1

**优先级：** P2

### 功能

提供简单页面：

* 输入 observable
* 查看 verdict
* 查看 raw evidence
* 导出 Markdown/HTML/JSON

### 验收标准

* 页面能跑通主要分析链路
* 不要求复杂前端框架，FastAPI templates 即可

---

# 16. Sprint 12：Production Hardening / Observability

## Epic S12-E1：Logging

### TASK S12-E1-T1

**文件：** `app/logging.py` 或等价模块
**优先级：** P1

### 功能

* JSON structured logging
* request id / trace id
* collector latency
* error classification

### 验收标准

* log 不泄漏 API key
* 重要流程均有日志

---

## Epic S12-E2：Metrics

### TASK S12-E2-T1

**优先级：** P1

### 建议指标

* collector_success_total
* collector_error_total
* collector_latency_ms
* cache_hit_ratio
* verdict_count_by_level

### 验收标准

* 至少有基础 metrics 导出点或日志统计

---

## Epic S12-E3：Hardening

### TASK S12-E3-T1

**优先级：** P1

### 内容

* 输入校验
* 并发限制
* API 限速
* batch 大小限制
* refresh 权限控制（如后续多用户）
* 超时和重试上限

### 验收标准

* 异常输入不会导致服务崩溃
* 批量分析可控

---

# 17. 测试 Backlog

## Epic TEST-E1：单元测试

### TASK TEST-E1-T1

`tests/test_models.py`

* 验证 Pydantic 模型

### TASK TEST-E1-T2

`tests/test_collectors.py`

* mock 外部 API 响应
* 校验解析字段

### TASK TEST-E1-T3

`tests/test_normalizers.py`

* collectors 结果 -> IPProfile

### TASK TEST-E1-T4

`tests/test_enrichers.py`

* 微软/Google/Cloudflare 标签识别

### TASK TEST-E1-T5

`tests/test_reputation_engine.py`

* 加减分逻辑正确
* score clamp 正常

### TASK TEST-E1-T6

`tests/test_verdict_engine.py`

* Low/Medium/High/Inconclusive 分层正确

---

## Epic TEST-E2：集成测试

### TASK TEST-E2-T1

`tests/test_api.py`

* FastAPI endpoint

### TASK TEST-E2-T2

`tests/test_cli.py`

* CLI lookup/report

### TASK TEST-E2-T3

`tests/test_end_to_end.py`

* mock 多源情报完成整个分析流程

---

## Epic TEST-E3：回归样本库

### TASK TEST-E3-T1

**目录：** `tests/fixtures/cases/`

### 样本类型

* known_benign_cloud.json
* known_google_service.json
* known_microsoft_service.json
* noisy_scanner.json
* suspicious_ip.json
* conflicting_evidence.json

### 验收标准

* 规则变化后可快速回归结果

---

# 18. 关键实现约束

OpenCode 必须遵守：

1. **Collector 不直接做最终打分**
2. **所有评分逻辑集中在 analyzers**
3. **所有结果必须附带 evidence**
4. **语义标签和规则尽量配置化**
5. **API 错误要降级，不可导致流程整体失败**
6. **所有 reporter 只负责展示，不写业务逻辑**
7. **query_engine 只做 orchestration，不嵌复杂规则**
8. **Contextual Risk Engine 必须可选**
9. **Batch 处理必须逐项容错**
10. **日志中不得输出密钥或敏感内部数据**

---

# 19. MVP Definition of Done

当以下内容全部完成时，可视为 MVP 交付：

## 必须功能

* 单 IP 查询
* AbuseIPDB / OTX / GreyNoise / RDAP / Reverse DNS
* IPProfile 标准化
* service catalog + semantic tagging
* reputation engine
* verdict engine
* JSON / Markdown / CLI 输出
* Typer CLI
* FastAPI API
* 单元测试基础覆盖

## 验收命令

```bash
tire lookup ip 8.8.8.8
tire report ip 52.123.129.14 --format md
uvicorn app.api:app --reload
```

---

# 20. 推荐的 OpenCode 执行顺序

最推荐执行顺序如下：

## 第一步

完成 Sprint 0 + Sprint 1

## 第二步

完成 Sprint 2 + Sprint 3

## 第三步

完成 Sprint 4 + Sprint 5
此时形成可演示 MVP

## 第四步

完成 Sprint 6 + Sprint 7
形成增强版 TI 工具

## 第五步

完成 Sprint 8 + Sprint 9
形成上下文感知安全分析工具

## 第六步

完成 Sprint 10 + Sprint 11 + Sprint 12
形成平台化版本

---

# 21. 建议的首批演示样例

OpenCode 完成 MVP 后，至少要验证以下样例：

1. `8.8.8.8`

   * 预期：Google 基础设施，Low

2. `1.1.1.1`

   * 预期：Cloudflare 基础设施，Low

3. `52.123.129.14`

   * 预期：Microsoft 服务基础设施，Low / Inconclusive-low depending on evidence

4. 一个 GreyNoise 标记为噪声扫描的样例 IP

   * 预期：Internet Noise 或 Medium-low

5. 一个公开高风险恶意 IP 样例

   * 预期：High / Critical

---

# 22. 交付要求

每个 Sprint 完成后，OpenCode 需要同时交付：

1. 代码
2. 更新后的 README
3. 测试
4. 示例命令
5. 一个最小可运行演示

---

# 23. 最终说明

本 Backlog 的目标是让 OpenCode 不是“写一个 IP 查询脚本”，而是逐步实现一个真正的：

**Threat Intelligence Reasoning Engine**

它应具备：

* 多源聚合
* 语义识别
* 噪声抑制
* 上下文修正
* 证据冲突处理
* 可解释结论
* 工程化接口

这套设计特别适合进一步接入：

* 蜜网数据
* 横向移动检测
* EDR / NDR 遥测
* IOC 图谱分析
* 你的内部威胁评分模型

---
