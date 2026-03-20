# TIRE 测试服务器部署手册

> 适用对象：人工运维人员、后续 AI Agent
>
> 适用场景：在测试服务器上“除原 SSL 证书外，其它全部从头开始”重新部署 TIRE。

---

## 目标

本手册固化一套已经实际验证通过的测试服务器部署流程，目标如下：

- 保留现有 SSL 证书目录；
- 删除旧应用代码、旧容器、旧运行数据；
- 基于仓库 `master` 分支重新部署；
- 使用根路径 `/` 对外提供服务；
- 通过独立 Nginx 容器提供 80/443 入口；
- 测试环境默认语言设置为中文（`LANGUAGE=zh`）。

---

## 当前已验证环境

- 服务器：`root@45.136.13.56`
- 部署目录：`/opt/tire`
- 证书保留目录：`/srv/letsencrypt/etc`
- ACME challenge 目录：`/srv/letsencrypt/www`
- 外部测试域名：`tire.rswitch.dev`

---

## 重要说明

### 1. 本流程会删除什么

以下内容会被删除并重建：

- 旧容器（`tire-nginx`、`tirev2-app`、`tire-app`）
- 旧 Docker volume（TIRE 相关运行数据）
- 旧代码目录（`/opt/tire`、`/opt/tirev2`）

### 2. 本流程不会删除什么

以下内容会保留：

- `/srv/letsencrypt/...` 证书目录
- 服务器系统环境
- SSH 配置

### 3. Fernet Key 说明

部署时必须生成并写入新的：

- `TIRE_FERNET_KEY`
- `SESSION_SECRET_KEY`

如果旧环境没有固定 `TIRE_FERNET_KEY`，那么旧数据库中加密保存的 API Key / LLM Key 通常无法恢复，应在新环境中重新录入。

---

## 第一步：登录服务器

```bash
ssh root@45.136.13.56
```

---

## 第二步：删除旧部署（保留证书）

```bash
docker rm -f tire-nginx tirev2-app tire-app 2>/dev/null || true

docker volume rm \
  tire_tire-cache \
  tirev2_tirev2-admin \
  tirev2_tirev2-cache \
  tirev2_tirev2-data \
  tirev2_tirev2-storage 2>/dev/null || true

rm -rf /opt/tire /opt/tirev2
```

执行后可简单确认：

```bash
docker ps -a
docker volume ls
ls -la /opt
```

---

## 第三步：重新拉取代码

```bash
git clone https://github.com/kylecui/ipit.git /opt/tire
cd /opt/tire
git checkout master
git pull origin master
```

可确认最近提交：

```bash
git log --oneline -5
```

---

## 第四步：初始化新的 `.env`

```bash
cd /opt/tire
cp .env.example .env
vim .env
```

至少设置以下值：

```dotenv
LANGUAGE=zh
ROOT_PATH=
TIRE_PORT=8000
LOG_LEVEL=INFO
PUBLIC_HOST=tire.rswitch.dev
ADMIN_PASSWORD=admin
```

### 生成新的密钥

```bash
python3 - <<'PY'
from cryptography.fernet import Fernet
print("TIRE_FERNET_KEY=" + Fernet.generate_key().decode())
print("SESSION_SECRET_KEY=" + Fernet.generate_key().decode())
PY
```

把输出结果写回 `.env`。

如果还需要接入外部能力，再补充：

- 插件 API keys
- LLM 配置

---

## 第五步：启动应用

```bash
cd /opt/tire
docker compose up -d --build
```

检查容器：

```bash
docker compose ps
docker compose logs --tail=100 tirev2-app
```

检查运行环境变量：

```bash
docker compose exec tirev2-app /bin/sh -lc 'printenv | grep -E "^(LANGUAGE|ROOT_PATH|TIRE_PORT)="'
```

预期至少包含：

```text
LANGUAGE=zh
ROOT_PATH=
TIRE_PORT=8000
```

---

## 第六步：准备 Nginx 实际配置

复制示例文件：

```bash
cp /opt/tire/nginx/nginx.conf.example /opt/tire/nginx/nginx.active.conf
vim /opt/tire/nginx/nginx.active.conf
```

至少替换以下内容：

- `your.domain.example` → `tire.rswitch.dev`
- `/path/to/your/fullchain.pem` → `/srv/letsencrypt/etc/live/tire.rswitch.dev/fullchain.pem`
- `/path/to/your/privkey.pem` → `/srv/letsencrypt/etc/live/tire.rswitch.dev/privkey.pem`

说明：

- 本次测试环境继续复用保留的证书目录；
- Nginx 容器将通过 volume 挂载方式读取这些证书。

---

## 第七步：启动独立 Nginx 容器

```bash
docker rm -f tire-nginx 2>/dev/null || true

docker run -d \
  --name tire-nginx \
  --restart unless-stopped \
  --network tire_tirev2-net \
  -p 80:80 \
  -p 443:443 \
  -v /opt/tire/nginx/nginx.active.conf:/etc/nginx/conf.d/default.conf:ro \
  -v /srv/letsencrypt/www:/var/www/letsencrypt:ro \
  -v /srv/letsencrypt/etc:/srv/letsencrypt/etc:ro \
  nginx:alpine
```

验证配置：

```bash
docker exec tire-nginx nginx -t
```

---

## 第八步：验证部署

### 1. 容器状态

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
```

预期至少看到：

- `tirev2-app`
- `tire-nginx`

### 2. 健康检查

```bash
curl -k -H "Host: tire.rswitch.dev" https://127.0.0.1/healthz
```

预期：

```json
{"status":"healthy","service":"threat-intel-reasoning-engine"}
```

### 3. 根路径入口

```bash
curl -k -i -H "Host: tire.rswitch.dev" https://127.0.0.1/
```

预期：

- `303 See Other`
- `location: /admin/login?next=%2F`

### 4. Host 限制

```bash
curl -k -I -H "Host: not-allowed.example" https://127.0.0.1/
```

如果限制生效，通常会直接断开连接，例如：

```text
curl: (56) Failure when receiving data from the peer
```

### 5. 默认中文界面

```bash
curl -k -L -H "Host: tire.rswitch.dev" https://127.0.0.1/ | head -n 40
```

可确认页面中出现：

- `<html lang="zh">`
- `登录`
- `管理后台`

---

## 本次已验证结果

以下结果已在测试服务器上验证通过：

- `tirev2-app` 正常启动且 healthy
- `tire-nginx` 正常监听 `80/443`
- `/healthz` 正常返回 200
- `/` 返回 `303` 并跳转到 `/admin/login?next=%2F`
- 非目标 Host 被拒绝
- 登录页默认中文（`<html lang="zh">`）

---

## 后续更新方式

后续如果只是更新代码，不需要重做全量清理，可执行：

```bash
ssh root@45.136.13.56
cd /opt/tire
git pull origin master
docker compose up -d --build
docker restart tire-nginx
```

如果 `.env` 保持不变，则：

- `LANGUAGE=zh` 会持续生效；
- `TIRE_FERNET_KEY` 和 `SESSION_SECRET_KEY` 会保持稳定；
- 已录入的密钥类配置可以继续使用。
