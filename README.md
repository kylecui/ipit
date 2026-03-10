# Threat Intelligence Reasoning Engine (TIRE)

一个多源威胁情报分析和推理引擎，用于IP/域名/URL可观测对象的分析。

## 🚀 快速开始

### 1. 安装

```bash
# 克隆仓库
git clone <repository-url>
cd threat-intel-reasoning-engine

# 创建虚拟环境（推荐使用uv）
uv venv
source .venv/bin/activate  # 或在Windows: .venv\Scripts\activate

# 安装依赖
uv pip install -r requirements.txt
```

### 2. 配置

复制环境文件并设置API密钥：

```bash
cp .env.example .env
# 编辑 .env 文件，添加您的API密钥（可选，但推荐）
```

### 3. 运行

#### CLI 快速测试
```bash
uv run python -m app.main lookup 8.8.8.8
```

#### 启动Web界面
```bash
uv run uvicorn app.api:app --reload
# 访问 http://127.0.0.1:8000/
```

#### 启动API服务器
```bash
uv run uvicorn app.api:app --reload
# API文档: http://127.0.0.1:8000/docs
```

## 📋 工具能力

TIRE 不是简单的声誉检查器，它提供：

- **多源情报收集**：整合9个外部威胁情报源（AbuseIPDB、OTX、GreyNoise、VirusTotal等）
- **语义服务识别**：识别云服务、CDN、Microsoft/Google服务等，减少误报
- **上下文感知分析**：考虑端口、方向、主机名、进程等上下文信息
- **可解释的判决**：提供证据、分数调整、语义标签和建议行动
- **多层分析**：声誉、噪音、上下文、内部遥测分析
- **多种输出格式**：CLI、JSON、Markdown、HTML、Web界面
- **批量处理**：支持CSV批量分析
- **缓存机制**：SQLite缓存提升性能
- **规则外部化**：YAML配置文件驱动的评分和行动规则

典型输出判决：
- Low / Medium / High / Critical
- Benign Service / Internet Noise / Needs Context / Inconclusive

## 🎯 使用方法

### CLI 使用

#### 基本IP查询
```bash
uv run python -m app.main lookup 8.8.8.8
```

#### 生成报告
```bash
# Markdown格式
uv run python -m app.main report 8.8.8.8 --format md --output report.md

# JSON格式
uv run python -m app.main report 8.8.8.8 --format json
```

#### 上下文感知分析
```bash
uv run python -m app.main analyze 8.8.8.8 \
  --direction outbound \
  --port 443 \
  --hostname example.com \
  --process chrome.exe
```

#### 批量分析
```bash
uv run python -m app.main batch observables.csv --format json --output results.json
```

### API 使用

#### 健康检查
```bash
curl http://localhost:8000/healthz
```

#### IP分析
```bash
curl http://localhost:8000/api/v1/ip/8.8.8.8
```

#### 上下文分析
```bash
curl -X POST http://localhost:8000/api/v1/analyze/ip \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "8.8.8.8",
    "context": {
      "direction": "outbound",
      "port": 53,
      "protocol": "udp"
    }
  }'
```

### Web界面使用

1. 启动服务器：`uv run uvicorn app.api:app --reload`
2. 打开浏览器访问 `http://127.0.0.1:8000/`
3. 输入IP地址，点击"Analyze IP"
4. 查看Bootstrap样式的分析结果

## 📊 示例输出

### CLI 输出示例
```
Threat Intelligence Analysis for 8.8.8.8
======================================

Verdict: Low
Summary: Google Public DNS - Known benign infrastructure
Confidence: 95.0%

Evidence:
✓ Google service identified via reverse DNS (dns.google)
✓ Low reputation score from multiple sources
✓ No malicious activity detected

Recommended Action: Allow - Benign infrastructure
```

### API 响应示例
```json
{
  "object_type": "ip",
  "object_value": "8.8.8.8",
  "level": "Low",
  "summary": "Google Public DNS - Known benign infrastructure",
  "confidence": 0.95,
  "final_score": 15,
  "tags": ["cloud_provider", "google_service", "dns"],
  "decision": "allow",
  "evidence": [...]
}
```

## ⚙️ 高级配置

### 环境变量

```env
# API密钥（可选）
ABUSEIPDB_API_KEY=your_key_here
OTX_API_KEY=your_key_here
GREYNOISE_API_KEY=your_key_here
VT_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here

# 性能设置
CACHE_TTL_HOURS=24
HTTP_TIMEOUT_SECONDS=15
MAX_RETRIES=2
LOG_LEVEL=INFO
```

### 自定义规则

编辑 `rules/` 目录下的YAML文件来自定义：
- `scoring_rules.yaml`: 评分规则
- `action_rules.yaml`: 行动规则
- `service_catalog.yaml`: 服务目录

## 🧪 测试

运行测试套件：
```bash
uv run pytest
```

推荐测试类别：
- 模型验证
- 收集器解析
- 标准化输出
- 语义标签
- 声誉评分
- 判决生成
- API端点测试

## 🏗️ 架构概览

```
输入层 (CLI/API/Web/Batch)
    ↓
查询编排 (QueryEngine)
    ↓
收集器 → 标准化器 → 丰富器 → 分析器 → 判决 → 报告器
    ↑           ↑          ↑         ↑        ↑       ↑
外部源    IP/域名规范  语义标签   多层分析  证据融合  多格式输出
```

## 📚 设计原则

1. **收集器不评分**：收集器仅收集数据，不进行最终评分
2. **所有评分在分析器中**：评分逻辑集中在分析器组件
3. **分析器发出证据**：所有分析器必须发出证据项
4. **语义标签驱动**：尽可能使用YAML规则驱动语义标签
5. **容错性**：查询编排必须容忍部分收集器失败
6. **报告器无业务逻辑**：报告器仅负责呈现，不包含业务逻辑
7. **上下文可选**：上下文分析必须是可选的
8. **批量容错**：批量分析必须是项目级容错的
9. **敏感配置不打印**：永远不要在日志中打印敏感配置
10. **允许不确定输出**：引擎必须允许不确定的输出

## 🔄 开发状态

✅ 已完成 Sprint 0-11：
- MVP核心功能（收集、标准化、分析、报告）
- 高级功能（缓存、规则外部化、上下文分析、图相关性）
- Web界面和仪表板

🚧 进行中 Sprint 12：
- 生产级强化（日志、指标、验证、限速）

## 📝 许可证与注意事项

本项目旨在防御性安全分析、SOC分流、威胁狩猎支持和可解释的威胁情报推理。

它不应被实现为单源黑名单查找工具。其核心价值在于：
- 多源情报融合
- 语义误报减少
- 上下文感知风险推理
- 可解释的证据驱动判决

