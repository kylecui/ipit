# Threat Intelligence Reasoning Engine
## 完整安全工具设计文档

Version: 2.0  
Date: 2026-03-09  
Audience: OpenCode / AI 开发系统 / 安全工程研发团队

---

# 1. 项目定位

## 1.1 项目名称

推荐正式名称：

**Threat Intelligence Reasoning Engine**

推荐仓库名：

**threat-intel-reasoning-engine**

推荐 CLI 名称：

**tire**

---

## 1.2 项目目标

构建一个可扩展的威胁情报分析平台，用于：

1. 查询任意 IP / Domain / URL 的公开威胁情报
2. 聚合多源外部情报与内部遥测数据
3. 自动识别资产归属与服务语义
4. 结合行为上下文给出风险评估
5. 输出可解释、可交付、可审计的分析报告
6. 支持 CLI / API / Web / 批量分析 / 规则引擎 / 图谱关联

---

## 1.3 设计原则

系统必须遵循以下原则：

1. **不依赖单一情报源**
2. **允许证据冲突**
3. **允许“不确定”结论**
4. **优先减少误报**
5. **支持解释性输出**
6. **支持服务语义识别**
7. **支持上下文驱动分析**
8. **支持内部情报与外部情报融合**
9. **支持离线缓存与异步分析**
10. **所有输出可审计、可追溯**

---

# 2. 核心设计思想

## 2.1 传统 Reputation 工具的问题

传统 IP 查询工具通常存在以下问题：

1. 只看单个平台分数
2. 无法识别云厂商 / CDN / 邮件网关 / Office / Defender 等合法服务
3. 无法识别互联网背景噪声
4. 无法结合上下文行为
5. 只能输出“高/低分”，不能解释原因
6. 对共享 IP、Anycast、CDN 边缘节点误报严重

因此，本项目不能只是做一个 “IP 黑名单查询器”。

---

## 2.2 本系统的核心能力

本系统核心能力不是“查分”，而是做四件事：

### A. 证据收集
从多个外部/内部来源收集证据。

### B. 证据标准化
将异构情报归一为统一对象模型。

### C. 证据推理
基于规则、语义和上下文进行推理，而不是简单求平均。

### D. 证据解释
明确告诉使用者：

- 有哪些加分项
- 有哪些减分项
- 哪些证据冲突
- 哪些证据不足
- 为什么给出当前结论

---

# 3. 目标使用场景

## 3.1 场景一：单个 IP 查询

示例：

```bash
tire lookup ip 52.123.129.14
````

输出：

* ASN / 组织 / 国家
* 多源情报
* 服务语义标签
* 风险评分
* 最终结论
* 解释文本

---

## 3.2 场景二：安全告警判读

输入：

* IP
* 端口
* 协议
* 方向（入站/出站）
* 域名
* SNI
* 进程名
* 主机角色
* 时间戳

系统输出：

* reputation score
* contextual risk
* 最终 verdict
* 解释建议

---

## 3.3 场景三：批量 IOC 分析

输入：

```bash
tire batch iocs.csv
```

支持：

* 批量 IP
* 批量 domain
* 批量 URL

输出：

* JSON
* Markdown
* CSV
* HTML 报告

---

## 3.4 场景四：SOC / SIEM / SOAR 集成

通过 REST API 提供：

* 单个 IOC 分析
* 批量分析
* verdict 查询
* 缓存查询
* 风险画像提取

---

## 3.5 场景五：蜜网 / 内部遥测增强

系统可以融合用户自己的：

* 蜜网命中日志
* 横向移动探测日志
* 端口访问画像
* IDS/NIDS/EDR 检测日志
* 内部白名单/黑名单
* 攻击链规则库

从而把工具升级为：

> 外部情报 + 内部行为 = 更可靠的威胁推理引擎

---

# 4. 支持的对象类型

系统设计时必须支持以下实体对象，而不是只支持 IP：

| 对象类型            | 示例                                                     |
| --------------- | ------------------------------------------------------ |
| IP              | 8.8.8.8                                                |
| Domain          | ecs.office.com                                         |
| URL             | [https://example.com/login](https://example.com/login) |
| ASN             | AS8075                                                 |
| Hostname        | dual-s-msedge.net                                      |
| Certificate     | subject / issuer / SAN                                 |
| Process Context | powershell.exe / curl / chrome                         |
| Flow Context    | 5元组 + 时序                                               |
| Internal Host   | 某终端 / 某服务器                                             |
| Threat Event    | 某次告警或会话                                                |

第一阶段可以以 IP 为主，但数据模型必须为多实体扩展预留空间。

---

# 5. 总体系统架构

```text
+------------------------------------------------------+
|                   User Interfaces                    |
|------------------------------------------------------|
| CLI | REST API | Web UI | Batch Job | SIEM Adapter   |
+-------------------------------+----------------------+
                                |
                                v
+------------------------------------------------------+
|                Query Orchestration Layer             |
|------------------------------------------------------|
| Input Validation | Cache | Scheduling | Retry | Rate |
+-------------------------------+----------------------+
                                |
                                v
+------------------------------------------------------+
|                 External Intel Collectors            |
|------------------------------------------------------|
| AbuseIPDB | OTX | GreyNoise | VirusTotal | RDAP      |
| IPinfo | Passive DNS | WHOIS | Shodan | Censys       |
+-------------------------------+----------------------+
                                |
                                v
+------------------------------------------------------+
|                 Internal Telemetry Collectors        |
|------------------------------------------------------|
| Honeynet | NIDS | EDR | Firewall | DNS Logs | Flow   |
+-------------------------------+----------------------+
                                |
                                v
+------------------------------------------------------+
|                 Normalization & Entity Layer         |
|------------------------------------------------------|
| IPProfile | DomainProfile | URLProfile | EntityGraph |
+-------------------------------+----------------------+
                                |
                                v
+------------------------------------------------------+
|                  Analysis & Reasoning Layer          |
|------------------------------------------------------|
| Reputation Engine                                    |
| Semantic Classification Engine                       |
| Noise Identification Engine                          |
| Contextual Risk Engine                               |
| Evidence Conflict Resolver                           |
| Graph Correlation Engine                             |
+-------------------------------+----------------------+
                                |
                                v
+------------------------------------------------------+
|                Verdict & Explanation Layer           |
|------------------------------------------------------|
| Score | Level | Confidence | Evidence | Narrative    |
+-------------------------------+----------------------+
                                |
                                v
+------------------------------------------------------+
|                 Output & Integration Layer           |
|------------------------------------------------------|
| JSON | Markdown | HTML | CSV | API | Web Dashboard  |
+------------------------------------------------------+
```

---

# 6. 模块划分

系统按以下一级模块实现：

```text
tire/
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
└── docs/
```

---

# 7. 模块详细设计

# 7.1 models

定义核心对象模型。

## 7.1.1 IPProfile

```python
class IPProfile(BaseModel):
    ip: str
    version: int
    asn: str | None = None
    organization: str | None = None
    country: str | None = None
    network: str | None = None
    rdns: list[str] = []
    hostnames: list[str] = []
    tags: list[str] = []
    sources: dict[str, Any] = {}
    external_refs: dict[str, Any] = {}
    timestamps: dict[str, datetime] = {}
```

## 7.1.2 DomainProfile

```python
class DomainProfile(BaseModel):
    domain: str
    apex_domain: str | None = None
    registrar: str | None = None
    created_at: datetime | None = None
    resolved_ips: list[str] = []
    tags: list[str] = []
    sources: dict[str, Any] = {}
```

## 7.1.3 ContextProfile

```python
class ContextProfile(BaseModel):
    direction: str | None = None
    protocol: str | None = None
    port: int | None = None
    hostname: str | None = None
    sni: str | None = None
    process_name: str | None = None
    process_path: str | None = None
    host_role: str | None = None
    timestamp: datetime | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
```

## 7.1.4 EvidenceItem

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

## 7.1.5 Verdict

```python
class Verdict(BaseModel):
    object_type: str
    object_value: str
    reputation_score: int
    contextual_score: int
    final_score: int
    level: str
    confidence: float
    decision: str
    summary: str
    evidence: list[EvidenceItem] = []
    tags: list[str] = []
```

---

# 7.2 collectors

负责外部情报采集。

每个 collector 必须实现统一接口：

```python
class BaseCollector(Protocol):
    name: str

    async def query(self, observable: str) -> dict:
        ...
```

所有 collector 都必须：

1. 支持超时控制
2. 支持重试
3. 支持 API 配额控制
4. 支持缓存
5. 支持错误降级
6. 不允许异常直接中断主流程

---

## 7.2.1 必选 Collector（Phase 1）

### AbuseIPDB

用途：

* abuseConfidenceScore
* totalReports
* usageType
* isp
* domain

### OTX

用途：

* pulse count
* indicator reputation
* related hostnames

### GreyNoise

用途：

* benign / malicious / unknown
* noise
* riot
* actor / classification

### RDAP

用途：

* ASN
* network
* org
* country

### Reverse DNS

用途：

* rdns
* hostname clues

---

## 7.2.2 扩展 Collector（Phase 2）

### VirusTotal

用途：

* malicious/suspicious counts
* related domains
* communicating files
* last_analysis_stats

### IPinfo / BGPView

用途：

* ASN / route / company profile

### Shodan / Censys

用途：

* exposed services
* banners
* certificates
* ports

### Passive DNS

用途：

* 历史域名/IP 关系

### Whois / RDAP domain

用途：

* domain creation / registrant

---

## 7.2.3 内部 Collector（Phase 3）

### Honeynet Collector

采集：

* 蜜网命中次数
* 目标端口组合
* 扫描模式

### Internal Flow Collector

采集：

* 会话方向
* 端口
* 时间模式
* 主机关联

### EDR Collector

采集：

* 发起进程
* 父进程
* 命令行
* 用户上下文

### DNS Collector

采集：

* 请求域名
* TTL
* 请求频率
* 首次/最近出现时间

---

# 7.3 normalizers

将各源异构数据转化为统一对象模型。

目标：

* 不让后续分析模块直接依赖外部 API 格式
* 所有分析都基于标准化对象执行

## 7.3.1 输入

```python
{
    "abuseipdb": {...},
    "otx": {...},
    "greynoise": {...},
    "rdap": {...},
    ...
}
```

## 7.3.2 输出

标准化 `IPProfile`

## 7.3.3 关键要求

1. 保留原始 source 数据
2. 提取高价值字段
3. 标准化字段命名
4. 尽量避免信息丢失
5. 支持 source 缺失

---

# 7.4 enrichers

用于补充高级语义，不直接打分。

## 7.4.1 Semantic Enricher

识别：

* cloud_provider
* cdn
* microsoft_service
* google_service
* mail_security
* internet_scanner
* vpn_exit
* tor_exit
* residential_proxy
* hosting_provider
* enterprise_service

识别逻辑来源：

* ASN
* organization
* hostname
* rdns
* known service catalog
* domain patterns

---

## 7.4.2 Service Catalog Enricher

维护一个本地可更新的服务语义库。

示例：

```yaml
microsoft:
  asns:
    - AS8075
  hostname_keywords:
    - office
    - msedge
    - teams
    - microsoft
    - xbox
  trust_tags:
    - cloud_provider
    - microsoft_service

google:
  asns:
    - AS15169
  hostname_keywords:
    - googleusercontent
    - 1e100.net
    - gvt1
```

这是误报抑制的关键模块。

---

## 7.4.3 Noise Enricher

识别：

* internet_background_noise
* common_scanner
* measurement_infra
* search_engine_bot
* cloud_health_check
* internet_crawler

来源：

* GreyNoise
* Shodan
* Known Scanner Fingerprints
* Internal pattern library

---

# 7.5 analyzers

这是系统核心。

---

## 7.5.1 Reputation Engine

职责：

基于外部情报计算 `reputation_score`

范围：

```text
0 - 100
```

### 加分项（风险增加）

| 条件                    |  分值 |
| --------------------- | --: |
| AbuseIPDB > 90        | +30 |
| AbuseIPDB > 70        | +20 |
| OTX pulse > 0 且高可信    | +20 |
| VT malicious 高        | +25 |
| GreyNoise = malicious | +20 |
| 暴露危险端口且 banner 可疑     | +15 |
| 命中已知恶意域名关系            | +20 |

### 减分项（风险降低）

| 条件                         |  分值 |
| -------------------------- | --: |
| 属于大型云厂商                    | -15 |
| 属于官方服务资产                   | -25 |
| GreyNoise = benign/riot    | -15 |
| rdns / hostname 语义强烈指向合法服务 | -20 |
| 仅零散社区上报                    | -10 |

### 输出

* reputation_score
* evidence list

---

## 7.5.2 Semantic Risk Adjustment Engine

职责：

根据资产语义修正 reputation 的解释和边界。

典型例子：

* Microsoft / Google / Cloudflare / Akamai 的 IP，即使被上报，也不应直接判高风险
* CDN/Anycast/shared IP 应降低恶意定性置信度
* 云厂商 IP 更适合“结合上下文分析”

输出：

* semantic_tags
* trust_adjustment
* caution_flags

---

## 7.5.3 Noise Identification Engine

职责：

识别互联网噪声与测绘行为。

输出标签：

* internet_noise
* common_scanner
* benign_scanner
* measurement_traffic
* background_radiation

作用：

* 降低误报
* 帮助 SOC 做优先级排序
* 区分“恶意攻击”和“背景扫描”

---

## 7.5.4 Contextual Risk Engine

职责：

将上下文行为纳入分析。

输入：

* port
* protocol
* direction
* hostname
* sni
* process_name
* process_path
* host_role
* time
* internal telemetry

### 样例规则

| 条件                                     |  调整 |
| -------------------------------------- | --: |
| 出站 443 + microsoft_service + office 域名 | -20 |
| 出站 443 + browser/office/defender 进程    | -15 |
| 入站 445/3389/22 对多目标探测                  | +25 |
| 单主机频繁扫描高危端口                            | +30 |
| 伴随恶意 PowerShell / curl 下载              | +25 |
| 同时命中多个 IOC                             | +30 |
| 仅单次短连接 ACK/RST 无后续                     | -10 |

输出：

* contextual_score
* contextual_evidence

---

## 7.5.5 Evidence Conflict Resolver

职责：

解决证据冲突。

示例冲突：

* AbuseIPDB 有上报，但 ASN 明确为 Microsoft
* OTX 有低质量 pulse，但 GreyNoise 标记 benign
* VT 有轻微命中，但 rdns 指向 Office 服务

策略：

1. 高权重源优先
2. 服务语义优先于弱社区上报
3. 行为上下文优先于孤立 reputation
4. 冲突无法解决时输出 `Inconclusive`

---

## 7.5.6 Graph Correlation Engine

职责：

建立对象关联图谱。

支持关系：

* IP -> Domain
* Domain -> URL
* IP -> ASN
* IP -> Certificate
* IP -> Malware Sample
* IP -> Internal Host
* Domain -> Resolved IPs
* Event -> IOC

用途：

* 发现恶意基础设施簇
* 发现共享服务语义
* 为报告提供补充上下文

第一阶段可以先做轻量内存图；后续支持 Neo4j / NetworkX。

---

# 8. Verdict 设计

## 8.1 最终分数

最终分数由三部分构成：

```text
final_score = reputation_score + contextual_adjustment + semantic_adjustment
```

分数边界必须 clamp 到 0-100。

---

## 8.2 最终等级

| Final Score | Verdict  |
| ----------- | -------- |
| 0 - 20      | Low      |
| 21 - 45     | Medium   |
| 46 - 75     | High     |
| 76 - 100    | Critical |

额外状态：

* `Inconclusive`
* `Needs Context`
* `Benign Service`
* `Internet Noise`

说明：
最终输出不应只给 High/Low，应该允许更贴近分析现实的标签。

---

## 8.3 决策字段

最终 verdict 必须包含：

* `level`
* `decision`
* `confidence`
* `summary`
* `key_evidence`
* `conflicting_evidence`
* `recommended_action`

示例：

```json
{
  "level": "Low",
  "decision": "allow_with_monitoring",
  "confidence": 0.84,
  "summary": "The IP is strongly associated with Microsoft cloud service infrastructure.",
  "recommended_action": "Do not block by reputation alone. Verify context if seen in suspicious inbound patterns."
}
```

---

# 9. 输出设计

# 9.1 CLI 输出

示例：

```text
Observable: 52.123.129.14
Type: IP
ASN: AS8075
Organization: Microsoft Corporation
Tags: cloud_provider, microsoft_service, shared_infrastructure

Reputation Score: 18
Contextual Score: -10
Final Score: 8
Verdict: LOW
Confidence: 0.86

Key Evidence:
- ASN belongs to Microsoft
- hostname relationship indicates office service
- no strong malicious indicators from major sources
- weak community abuse evidence only

Recommended Action:
Allow by default, but verify context if associated with suspicious inbound activity
```

---

# 9.2 JSON 输出

供 API / SOAR / SIEM 使用。

必须结构化，便于后续自动化。

---

# 9.3 Markdown 报告

用于人工交付。

结构建议：

1. 目标对象
2. 分析结论摘要
3. 基础画像
4. 外部情报摘要
5. 语义识别结论
6. 上下文分析
7. 冲突证据说明
8. 最终结论
9. 处置建议
10. 原始参考来源

---

# 9.4 HTML 报告

用于 Web 展示或导出。

---

# 10. API 设计

## 10.1 单对象查询

```http
GET /api/v1/ip/{ip}
```

支持 query 参数：

* `with_context=true`
* `with_raw=true`
* `refresh=true`

---

## 10.2 上下文分析

```http
POST /api/v1/analyze/ip
```

body 示例：

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

## 10.3 批量分析

```http
POST /api/v1/batch
```

body：

```json
{
  "observables": [
    {"type": "ip", "value": "1.1.1.1"},
    {"type": "ip", "value": "8.8.8.8"}
  ]
}
```

---

## 10.4 健康检查

```http
GET /healthz
GET /readyz
```

---

# 11. CLI 设计

命令建议：

```bash
tire lookup ip 8.8.8.8
tire lookup domain ecs.office.com
tire analyze ip 52.123.129.14 --port 443 --direction outbound --hostname ecs.office.com
tire report ip 52.123.129.14 --format md
tire batch input.csv --format json
tire cache clear
tire rules validate
```

---

# 12. 项目目录设计

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
│   ├── virustotal.py
│   ├── reverse_dns.py
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
│   ├── test_collectors.py
│   ├── test_normalizers.py
│   ├── test_reputation_engine.py
│   ├── test_contextual_engine.py
│   ├── test_verdict_engine.py
│   └── fixtures/
├── docs/
│   ├── design.md
│   └── api.md
├── requirements.txt
├── README.md
└── .env.example
```

---

# 13. 配置设计

环境变量：

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

---

# 14. 缓存与存储设计

## 14.1 缓存

必须支持 TTL 缓存，避免频繁打外部 API。

缓存对象：

* 原始 collector 响应
* 标准化 profile
* 最终 verdict

默认 TTL：

* 外部声誉数据：24h
* 被动 DNS：12h
* 语义库：本地静态版本 + 定期刷新

实现建议：

* MVP：SQLite
* 服务化：Redis + PostgreSQL

---

## 14.2 审计与溯源

所有分析结果必须可追溯：

* 何时查询
* 查询了哪些来源
* 使用了哪些规则
* 哪些 evidence 参与了 verdict
* 版本号是什么

用于后续审计与规则回放。

---

# 15. 规则系统设计

规则不要全部写死在 Python 里，应配置化。

## 15.1 scoring_rules.yaml

```yaml
reputation:
  abuseipdb:
    high:
      threshold: 90
      delta: 30
    medium:
      threshold: 70
      delta: 20

  otx:
    pulse_positive_delta: 20

  greynoise:
    malicious_delta: 20
    benign_delta: -15

semantic_adjustments:
  cloud_provider: -15
  official_service: -25
  shared_infrastructure: -10

contextual:
  outbound_https_known_service: -20
  inbound_smb_scan: 25
  suspicious_download_process: 25
```

---

## 15.2 service_catalog.yaml

用于管理合法服务语义。

---

## 15.3 action_rules.yaml

根据 verdict 给出处置建议。

示例：

```yaml
actions:
  Low:
    decision: allow_with_monitoring
  Medium:
    decision: investigate
  High:
    decision: alert_and_review
  Critical:
    decision: contain_or_block
  Inconclusive:
    decision: collect_more_context
```

---

# 16. 安全性设计

工具本身也必须安全。

## 16.1 输入校验

* 严格校验 IP / Domain / URL 格式
* 限制批量大小
* 防止命令注入
* 防止 SSRF 型误用（如果后续支持 URL fetch）

## 16.2 密钥保护

* API key 只允许从环境变量或密钥管理系统读取
* 禁止写入日志
* 禁止出现在异常堆栈中

## 16.3 请求控制

* 所有外部请求必须设置 timeout
* 允许 retry，但必须有限次
* 限制并发，防止 API 配额打爆

## 16.4 报告脱敏

如果接入内部遥测，报告输出时要可配置是否脱敏：

* 主机名
* 用户名
* 内网 IP
* 进程路径

---

# 17. 可观测性设计

必须有以下监控：

* collector 成功率
* collector 延迟
* API 调用次数
* cache hit ratio
* verdict 分布
* error rate
* queue backlog（若异步）

日志需结构化，建议 JSON logging。

---

# 18. 测试设计

## 18.1 单元测试

覆盖：

* collector 解析逻辑
* normalizer
* semantic_enricher
* reputation_engine
* contextual_engine
* verdict_engine

## 18.2 集成测试

使用 mock 响应测试端到端分析流程。

## 18.3 回归测试

构建一个固定样本集：

* 明确恶意 IP
* 明确合法云服务 IP
* 背景噪声 IP
* 共享 CDN IP
* 证据冲突 IP

确保规则修改后结果不失控。

---

# 19. 交付阶段规划

## Phase 1：可用 MVP

目标：

* 单 IP 查询
* 4 个外部源
* 基础语义识别
* reputation score
* markdown/json 输出
* CLI + API

必须交付：

* AbuseIPDB
* OTX
* GreyNoise
* RDAP
* Reverse DNS
* Semantic Enricher
* Reputation Engine
* Verdict Engine
* Markdown Reporter

---

## Phase 2：增强分析

增加：

* VirusTotal
* Shodan
* batch analysis
* HTML report
* rule config
* service catalog
* noise engine

---

## Phase 3：上下文感知

增加：

* ContextProfile 输入
* process / port / direction 分析
* host role 修正
* internal telemetry ingest
* evidence conflict resolver

---

## Phase 4：图谱与平台化

增加：

* entity graph
* Web UI
* Neo4j / graph backend
* SIEM/SOAR adapters
* scheduled refresh
* IOC watchlist

---

# 20. OpenCode 实施要求

OpenCode 在生成代码时必须遵守：

1. 所有模块解耦
2. Collector 统一接口
3. 配置与规则外置
4. 所有引擎输出 evidence
5. 所有 verdict 必须解释化
6. 所有 API 异常必须降级而非崩溃
7. 不允许在 collector 里直接做复杂打分逻辑
8. 打分逻辑集中在 analyzers 中
9. 模板与业务逻辑分离
10. 所有模型使用 Pydantic

---

# 21. 示例分析流程

输入：

```json
{
  "ip": "52.123.129.14",
  "context": {
    "direction": "outbound",
    "port": 443,
    "hostname": "ecs.office.com",
    "process_name": "MsMpEng.exe",
    "host_role": "workstation"
  }
}
```

执行流程：

1. collectors 查询 AbuseIPDB / OTX / GreyNoise / RDAP / reverse DNS
2. normalizer 生成 IPProfile
3. semantic_enricher 打标签：

   * cloud_provider
   * microsoft_service
   * shared_infrastructure
4. reputation_engine 计算基础风险
5. contextual_engine 根据 outbound + 443 + known service + defender process 降权
6. conflict_resolver 处理社区上报与微软归属冲突
7. verdict_engine 输出最终结论：

   * Low
   * allow_with_monitoring

---

# 22. 最终输出示例

```json
{
  "object_type": "ip",
  "object_value": "52.123.129.14",
  "reputation_score": 18,
  "contextual_score": -10,
  "final_score": 8,
  "level": "Low",
  "confidence": 0.86,
  "decision": "allow_with_monitoring",
  "summary": "IP is strongly associated with Microsoft service infrastructure and current context matches benign outbound Office/Defender traffic.",
  "tags": [
    "cloud_provider",
    "microsoft_service",
    "shared_infrastructure"
  ],
  "evidence": [
    {
      "source": "rdap",
      "category": "ownership",
      "severity": "low",
      "title": "IP belongs to Microsoft ASN",
      "detail": "ASN resolved to Microsoft Corporation",
      "score_delta": -15,
      "confidence": 0.95
    },
    {
      "source": "semantic",
      "category": "service",
      "severity": "low",
      "title": "Known Microsoft service context",
      "detail": "hostname suggests Office/Defender related infrastructure",
      "score_delta": -20,
      "confidence": 0.9
    }
  ]
}
```

---

# 23. 结论

本项目不应被实现为简单的 “IP reputation 查询器”，而应实现为：

> **Threat Intelligence Reasoning Engine**

它的核心价值是：

* 聚合多源证据
* 自动识别合法服务语义
* 结合上下文修正风险
* 输出可解释、可审计的结论
* 支持你后续接入蜜网、横向移动、内部遥测与恶意软件画像

这会使工具从一个普通查询器，升级为一个真正可用于 SOC、告警判读和研究分析的安全平台。


## 开发顺序


### 第一批
先做基础骨架与 MVP：
- models
- collectors: abuseipdb / otx / greynoise / rdap / reverse_dns
- normalizer
- semantic_enricher
- reputation_engine
- verdict_engine
- markdown/json/cli reporter
- typer CLI
- fastapi API

### 第二批
再做增强：
- rules yaml
- cache
- html report
- batch
- virustotal
- shodan
- noise_engine

### 第三批
最有价值的差异化能力：
- contextual_risk_engine
- honeynet collector
- internal flow collector
- conflict_resolver
- graph correlator

