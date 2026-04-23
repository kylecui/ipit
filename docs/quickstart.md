# TIRE V2 快速上手

> 目标：从零开始，10 分钟内完成第一次 IP 威胁分析。

## 前提条件

- Python 3.11+（推荐使用 [uv](https://github.com/astral-sh/uv) 管理）
- Docker 24+ 和 Docker Compose v2（生产部署）
- Git

## 1. 获取代码

```bash
git clone <repository-url>
cd ipit
```

## 2. 选择启动方式

### 方式 A：本地开发

```bash
# 创建虚拟环境
uv venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 安装依赖
uv pip install -r requirements.txt

# 准备配置
cp .env.example .env
```

编辑 `.env`，至少配置以下三项安全变量：

```ini
ADMIN_PASSWORD=your-secure-password
SESSION_SECRET_KEY=your-random-secret
TIRE_FERNET_KEY=<见下方生成方法>
```

生成 Fernet Key：

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

启动服务：

```bash
uv run uvicorn app.api:app --reload
```

浏览器访问 http://127.0.0.1:8000/

### 方式 B：Docker 部署

```bash
cp .env.example .env
# 编辑 .env（同上配置安全变量）
docker compose up -d
```

验证服务：

```bash
curl http://localhost:8000/healthz
# 预期返回: {"status":"healthy","service":"threat-intel-reasoning-engine"}
```

## 3. 第一次分析

1. 浏览器打开首页
2. 输入 `8.8.8.8`
3. 点击 **分析**
4. 查看分析结果：风险评分、证据列表、数据源状态

## 4. 配置管理后台

1. 访问 `/admin/login`
2. 使用账号 `admin` / 你设置的 `ADMIN_PASSWORD` 登录
3. 进入 **共享 API 密钥** 页面，为需要的插件配置 API Key（如 AbuseIPDB、VirusTotal 等）
4. 配置后重新分析 IP，将获得更丰富的情报结果

## 5. CLI 快速测试

```bash
# 快速查询
uv run python -m app.main lookup 8.8.8.8 --format cli

# 生成报告
uv run python -m app.main report 8.8.8.8 --format md --output report.md

# 上下文分析
uv run python -m app.main analyze 192.168.1.1 --direction outbound --port 443

# 批量处理
uv run python -m app.main batch ips.csv --format json
```

所有命令支持 `--lang zh` 切换中文输出，`--refresh` 跳过缓存。

## 6. 生成详细报告

1. 完成 IP 分析后，点击 **生成详细报告**
2. 若已配置 LLM（管理后台 → LLM 设置），将生成 AI 增强报告
3. 未配置 LLM 时，系统自动回退为模板报告

---

## 下一步

- 详细部署方案 → [部署指南](deployment.md)
- 完整配置说明 → [配置参考](configuration.md)
- 管理后台操作 → [管理员指南](admin-guide.md)
- 常见问题 → [故障排查](troubleshooting.md)
- 插件开发 → [V2 插件架构](V2_PLUGIN_ARCHITECTURE.md)
