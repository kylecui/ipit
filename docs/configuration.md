# TIRE V2 配置指南

本文档提供了 TIRE V2 的详细配置参考，包括环境变量、插件配置、规则文件以及数据库说明。

## 环境变量参考

TIRE 使用 `.env` 文件管理基础配置。你可以参考项目根目录下的 `.env.example` 创建自己的 `.env` 文件。

### 安全与管理
| 变量 | 说明 | 默认值 | 必须 |
|---|---|---|---|
| ADMIN_PASSWORD | 初始管理员密码（仅在首次启动、无用户时使用） | admin | 生产环境必须修改 |
| SESSION_SECRET_KEY | Session 加密密钥，用于 Web 会话安全 | change-me-in-production | 生产环境必须修改 |
| TIRE_FERNET_KEY | API Key 加密存储密钥 (Fernet)，用于保护数据库中的密钥 | 无 | 生产环境必须设置 |

### 威胁情报 API 密钥
若不配置环境变量，且管理后台未配置对应密钥，则对应插件将跳过数据采集。
| 变量 | 说明 |
|---|---|
| ABUSEIPDB_API_KEY | AbuseIPDB API 密钥 |
| OTX_API_KEY | AlienVault OTX API 密钥 |
| GREYNOISE_API_KEY | GreyNoise API 密钥 |
| VT_API_KEY | VirusTotal API 密钥 |
| SHODAN_API_KEY | Shodan API_KEY |
| THREATBOOK_API_KEY | 微步在线 (ThreatBook) API 密钥 |
| TIANJIYOUMENG_API_KEY | 天际友盟 (TianJi YouMeng) API 密钥 |

### 性能设置
| 变量 | 说明 | 默认值 |
|---|---|---|
| CACHE_TTL_HOURS | 缓存生存时间（小时） | 24 |
| HTTP_TIMEOUT_SECONDS | HTTP 请求超时时间（秒） | 15 |
| MAX_RETRIES | 接口请求失败后的重试次数 | 2 |

### 应用配置
| 变量 | 说明 | 默认值 |
|---|---|---|
| LOG_LEVEL | 日志级别 (DEBUG, INFO, WARNING, ERROR) | INFO |
| LANGUAGE | 默认界面语言 (en, zh) | en |
| TIRE_PORT | 应用运行端口 | 8000 |
| ROOT_PATH | 反向代理路径前缀（如部署在 `/v2` 下时设置） | 空 |
| RESULT_STALENESS_DAYS | 结果过期天数（超过此天数将触发重新查询） | 7 |

### LLM 配置
用于生成 AI 叙述性报告。
| 变量 | 说明 | 默认值 |
|---|---|---|
| LLM_API_KEY | LLM API 密钥 | 无 |
| LLM_MODEL | 使用的模型名称 | gpt-4o |
| LLM_BASE_URL | API 基础 URL | https://api.openai.com/v1 |

---

## 插件配置文件 (config/plugins.yaml)

`config/plugins.yaml` 定义了所有可用插件的运行参数。

### 字段含义
- `enabled`: 是否启用该插件。
- `api_key_env`: 对应的环境变量名称，若不需要密钥则设为 `null`。
- `priority`: 运行优先级，数值越小越先执行。
- `config`: 插件特有的自定义配置项。
- `sandboxed`: 是否在隔离的子进程中运行（社区插件默认为 `true`）。
- `timeout`: 插件运行超时时间（秒）。
- `memory_limit_mb`: 插件内存限制（仅限 Linux）。

### 配置示例
```yaml
plugins:
  abuseipdb:
    enabled: true
    api_key_env: ABUSEIPDB_API_KEY
    priority: 10
    config:
      max_age_days: 90
      min_confidence: 25
```

---

## 规则文件

规则文件位于 `rules/` 目录下，支持热更新（修改后重启服务生效）。

- **rules/scoring_rules.yaml**: 定义各情报源的评分权重、触发条件、严重程度及证据模板。
- **rules/action_rules.yaml**: 定义评分阈值（Low, Medium, High, Critical）与对应的行动建议（如 `investigate`, `block`）及总结模板。
- **rules/service_catalog.yaml**: 已知服务识别模式，用于识别云厂商、CDN、搜索引擎等，通过语义标签减少误报。

---

## API Key 优先级链

TIRE V2 支持多层级的密钥管理，优先级如下：
1. **user_key**: 用户在个人设置中配置的私有密钥。
2. **shared_admin_key**: 管理员在后台配置并允许共享的密钥。
3. **env_var**: 服务器环境变量中配置的密钥（`.env` 文件）。
4. **None**: 若以上均未配置，插件将跳过。

---

## Fernet Key 生成方法

用于 `TIRE_FERNET_KEY` 的密钥可以使用以下命令生成：

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## 数据库文件位置

所有持久化数据均存储在 `storage/` 和 `cache/` 目录下：

- **storage/results.db**: 存储查询快照、历史记录及生成的分析报告。
- **cache/cache.db**: 存储带 TTL 的原始数据缓存。
- **admin/admin.db**: 存储用户信息、权限、加密后的 API 密钥、LLM 配置及审计日志。
