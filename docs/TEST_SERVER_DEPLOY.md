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
- `威胁情报推理引擎`

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

## 标准升级流程（已验证）

当仓库有新的代码提交（例如 Bug 修复、新功能、UI 调整）时，使用以下流程升级已部署的测试环境。**无需重做全量清理。**

### 前置条件

- 测试服务器已按本手册完成初始部署
- `.env` 中的密钥（`TIRE_FERNET_KEY`、`SESSION_SECRET_KEY`）未变动
- 无需修改 Nginx 配置（如需修改，参见下方说明）

### 执行步骤

```bash
ssh root@45.136.13.56
cd /opt/tire

# 1. 拉取最新代码
git pull origin master

# 2. 重新构建并重启应用容器
docker compose up -d --build

# 3. 如果本次更新涉及 Nginx 配置示例变更，需要同步并重启 Nginx
#    （大多数情况不需要此步骤）
# docker restart tire-nginx
```

### 验证升级结果

```bash
# 健康检查
curl -k -H "Host: tire.rswitch.dev" https://127.0.0.1/healthz
# 预期: {"status":"healthy","service":"threat-intel-reasoning-engine"}

# 确认页面变更生效（示例：检查登录页内容）
curl -k -L -s -H "Host: tire.rswitch.dev" https://127.0.0.1/ | head -n 40
```

### 升级范围说明

本流程会更新的内容：

- 应用代码（Python 后端、模板、i18n、规则文件等）
- Docker 镜像重新构建（如依赖包变更，会自动更新）

本流程**不会**影响的内容：

- `.env` 配置（密钥、语言设置等保持不变）
- SQLite 数据库（管理后台数据、缓存数据保持不变）
- Nginx 配置（`nginx.active.conf` 不会被覆盖）
- SSL 证书

### 特殊情况处理

**如果依赖包变更（requirements.txt 更新）：**
`docker compose up -d --build` 会自动检测并重新安装，无需额外操作。

**如果 Nginx 配置示例有变更：**
需要手动对比并合并更新：
```bash
diff /opt/tire/nginx/nginx.active.conf /opt/tire/nginx/nginx.conf.example
# 根据差异手动调整 nginx.active.conf，然后：
docker restart tire-nginx
```

**如果 `.env.example` 新增了必要配置项：**
对比并补充到 `.env`：
```bash
diff /opt/tire/.env /opt/tire/.env.example
# 根据差异手动补充新增项到 .env，然后重启：
docker compose up -d
```

### 已验证升级结果

以下升级场景已在测试服务器上实际验证通过：

- `git pull origin master` — Fast-forward 合并，无冲突
- `docker compose up -d --build` — 增量构建，仅重建变更层，耗时约 5 秒
- `/healthz` 返回 200，应用正常运行
- 登录页 UI 变更立即生效（"管理后台" → "威胁情报推理引擎"）
- `.env` 配置、数据库、Nginx 均未受影响
