# TIRE 部署指南 — 当前主线部署模式

## 前置条件

- 一台 Linux 服务器（推荐 Ubuntu 22.04+，2核4G）
- Docker 24+ 和 Docker Compose v2
- 威胁情报 API 密钥（可选，但推荐至少配置 AbuseIPDB）

---

## 当前部署原则

- 当前主系统为 **TIRE V2**
- 系统直接运行于根路径 `/`
- 对外访问 Host 应由部署者自行配置
- 如需 Host 限制，应由部署者在反向代理层启用并替换为自己的域名

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

浏览器打开你实际配置的域名，例如 `https://your.domain.example/`

---

## 常用运维命令

```bash
# 查看日志
docker compose logs -f tirev2-app

# 重启服务
docker compose restart tirev2-app

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

### 方式 1：Host 限制（当前推荐）

仓库中提供的是示例文件：

```text
nginx/nginx.conf.example
```

部署时建议先复制为你的实际配置文件，再替换域名和证书路径。仓库中的示例文件不能直接作为生产配置使用。若希望仅放行目标 Host，可参考：

```nginx
server {
    listen 80;
    server_name your.domain.example;
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name your.domain.example;
    location / {
        proxy_pass http://tire_backend;
    }
}

server {
    listen 80 default_server;
    server_name _;
    return 444;
}
```

### 方式 2：IP 白名单（可选增强）

编辑你复制后的实际 Nginx 配置文件，取消注释 IP 白名单部分：

```nginx
allow 10.0.0.0/8;         # 内网 A 类
allow 172.16.0.0/12;      # 内网 B 类
allow 192.168.0.0/16;     # 内网 C 类
allow 203.0.113.50/32;    # 替换为你的公司出口 IP
deny all;
```

修改后重载或重启你实际部署的 Nginx：

```bash
# 例如（宿主机 Nginx）
sudo nginx -s reload

# 或（独立容器化 Nginx）
docker restart <your-nginx-container>
```

### 方式 3：云厂商安全组

在云服务器控制台，配置安全组规则：
- 仅放行公司出口 IP 的 80/443 端口
- 放行 22 端口（SSH 管理，仅限运维 IP）

### 方式 4：Basic Auth

```bash
# 在服务器上生成密码文件
sudo apt install -y apache2-utils
htpasswd -c nginx/htpasswd tire-user

# 在 nginx.conf 的 location / 块中添加：
# auth_basic "TIRE Internal";
# auth_basic_user_file /etc/nginx/htpasswd;

# 如果你使用独立 Nginx 容器，请将该文件挂载到容器中的 /etc/nginx/htpasswd；
# 如果你使用宿主机 Nginx，请将其放到实际 Nginx 配置引用的位置。
```

---

## ROOT_PATH 说明

当前主线部署模式中，TIRE V2 直接运行于 `/`，因此通常应保持：

```bash
ROOT_PATH=
```

只有在部署于子路径时，才需要设置类似 `/subpath` 的前缀。

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
docker compose restart tirev2-app
```

---

## 故障排查

```bash
# 检查容器状态
docker compose ps

# 查看应用日志
docker compose logs tirev2-app --tail=50

# 查看 Nginx 日志（按你的实际部署方式选择）
docker logs <your-nginx-container> --tail=50
# 或
journalctl -u nginx -n 50 --no-pager

# 进入容器调试
docker compose exec tirev2-app /bin/bash

# 检查端口占用
ss -tlnp | grep 80
```

---

## Nginx 示例文件使用方式

```bash
cp nginx/nginx.conf.example /your/deploy/path/nginx.conf
```

然后根据你的环境至少替换以下内容：

1. `your.domain.example`
2. TLS 证书路径
3. 是否启用默认 Host 拒绝策略（`return 444`）

---

## 架构说明

```
  用户浏览器 / API 调用
         │
         ▼
   ┌──────────────┐
   │ Nginx :80/443│  Host限制、TLS、反向代理、安全头
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
