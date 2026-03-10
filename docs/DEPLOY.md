# TIRE 部署指南 — 内部测试环境

## 前置条件

- 一台 Linux 服务器（推荐 Ubuntu 22.04+，2核4G）
- Docker 24+ 和 Docker Compose v2
- 威胁情报 API 密钥（可选，但推荐至少配置 AbuseIPDB）

---

## 快速部署（5 分钟）

### 1. 克隆代码

```bash
git clone <repository-url> /opt/tire
cd /opt/tire
```

### 2. 配置环境变量

```bash
cp .env.example .env
vim .env
# 填写 API 密钥，调整端口等
```

### 3. 启动服务

```bash
docker compose up -d
```

### 4. 验证

```bash
# 健康检查
curl http://localhost/healthz
# 预期返回: {"status":"healthy","service":"threat-intel-reasoning-engine"}

# 测试分析
curl http://localhost/api/v1/ip/8.8.8.8
```

### 5. 访问 Web 界面

浏览器打开 `http://<服务器IP>/`

---

## 常用运维命令

```bash
# 查看日志
docker compose logs -f tire

# 重启服务
docker compose restart tire

# 更新代码后重新部署
git pull
docker compose up -d --build

# 停止服务
docker compose down

# 停止并清除缓存数据
docker compose down -v
```

---

## 安全加固（推荐）

### 方式 1：IP 白名单（推荐）

编辑 `nginx/nginx.conf`，取消注释 IP 白名单部分：

```nginx
allow 10.0.0.0/8;         # 内网 A 类
allow 172.16.0.0/12;      # 内网 B 类
allow 192.168.0.0/16;     # 内网 C 类
allow 203.0.113.50/32;    # 替换为你的公司出口 IP
deny all;
```

修改后重启 Nginx：

```bash
docker compose restart nginx
```

### 方式 2：云厂商安全组

在云服务器控制台，配置安全组规则：
- 仅放行公司出口 IP 的 80/443 端口
- 放行 22 端口（SSH 管理，仅限运维 IP）

### 方式 3：Basic Auth

```bash
# 在服务器上生成密码文件
sudo apt install -y apache2-utils
htpasswd -c nginx/htpasswd tire-user

# 在 nginx.conf 的 location / 块中添加：
# auth_basic "TIRE Internal";
# auth_basic_user_file /etc/nginx/htpasswd;

# 在 docker-compose.yml 的 nginx volumes 中添加：
# - ./nginx/htpasswd:/etc/nginx/htpasswd:ro
```

---

## 修改端口

默认端口为 80，如需修改：

```bash
# 方式 1：修改 .env
TIRE_PORT=8080

# 方式 2：启动时指定
TIRE_PORT=8080 docker compose up -d
```

---

## 规则热更新

`rules/` 目录已挂载为只读卷，修改规则文件后：

```bash
# 重启应用以加载新规则
docker compose restart tire
```

---

## 故障排查

```bash
# 检查容器状态
docker compose ps

# 查看应用日志
docker compose logs tire --tail=50

# 查看 Nginx 日志
docker compose logs nginx --tail=50

# 进入容器调试
docker compose exec tire /bin/bash

# 检查端口占用
ss -tlnp | grep 80
```

---

## 架构说明

```
  用户浏览器 / API 调用
         │
         ▼
  ┌──────────────┐
  │   Nginx :80  │  反向代理、安全头、IP白名单
  └──────┬───────┘
         │
         ▼
  ┌──────────────┐
  │  TIRE :8000  │  FastAPI + Uvicorn (2 workers)
  │              │  Web界面 + REST API + 健康检查
  └──────┬───────┘
         │
         ▼
  SQLite 缓存 (Docker Volume)
```

---

## 推荐云服务器配置

| 项目 | 推荐 |
|------|------|
| 厂商 | 阿里云 ECS / 腾讯云 CVM / 华为云 ECS |
| 规格 | 2核4G（轻量应用服务器亦可） |
| 系统 | Ubuntu 22.04 LTS |
| 磁盘 | 40G SSD |
| 带宽 | 5Mbps（内部测试足够） |
| 预算 | 约 50-150 元/月 |
