# TIRE V2 部署指南

本指南介绍如何使用 Docker 部署 TIRE V2 生产环境，包括与 V1 版本并行运行的配置及安全加固建议。

## 前提条件

在开始部署前，请确保您的服务器满足以下要求：

- **操作系统**: 推荐使用 Ubuntu 22.04 LTS 或更高版本。
- **Docker**: 版本 24.0+。
- **Docker Compose**: 版本 v2.0+。
- **硬件配置**:
  - CPU: 2 核
  - 内存: 4 GB
  - 磁盘: 40 GB SSD 或更高

## Docker 生产部署

### 1. 准备配置文件

克隆代码库后，进入项目根目录并创建环境变量文件：

```bash
cp .env.example .env
```

### 2. 配置关键变量

编辑 `.env` 文件，确保以下变量已正确配置：

- `ADMIN_PASSWORD`: 管理员后台默认登录密码。
- `SESSION_SECRET_KEY`: 用于会话签名的随机字符串。
- `TIRE_FERNET_KEY`: 用于加密存储 API 密钥的密钥。
  - 生成方法：`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
- `ROOT_PATH`: 应用部署的子路径（如 `/v2`），默认为空。
- `TIRE_PORT`: 容器对外映射的端口，默认 `8000`。

### 3. 启动服务

使用 Docker Compose 启动应用：

```bash
docker compose up -d
```

### 4. 健康检查

启动后，可以通过以下命令验证服务状态：

```bash
curl http://localhost:8000/healthz
```

预期返回：`{"status":"healthy","service":"threat-intel-reasoning-engine"}`

## V1/V2 并行部署

TIRE V2 支持与 V1 版本在同一台服务器上并行运行，互不干扰。

### 部署方案

- **V1 版本**: 部署在根路径 `/`。
- **V2 版本**: 部署在子路径 `/v2`。

### 配置步骤

1. **设置 V2 环境变量**:
   在 V2 的 `.env` 文件中设置 `ROOT_PATH=/v2`。

2. **配置 Nginx 反向代理**:
   在宿主机的 Nginx 配置中，将 `/v2` 的请求转发给 V2 应用容器：

   ```nginx
   location /v2/ {
       proxy_pass http://127.0.0.1:8000/v2/;
       proxy_set_header Host $host;
       proxy_set_header X-Real-IP $remote_addr;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto $scheme;
   }
   ```

3. **隔离性**:
   确保 V1 和 V2 使用不同的端口和持久化目录，以防数据冲突。

## 环境变量说明

以下是与部署相关的核心环境变量：

| 变量名 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `TIRE_PORT` | `8000` | 应用监听的端口。 |
| `ROOT_PATH` | (空) | 应用部署的子路径，如 `/v2`。 |
| `ADMIN_PASSWORD` | - | 管理员后台登录密码。 |
| `SESSION_SECRET_KEY` | - | 会话加密密钥，建议使用长随机字符串。 |
| `TIRE_FERNET_KEY` | - | API 密钥加密密钥（Fernet 格式）。 |
| `RESULT_STALENESS_DAYS` | `7` | 查询结果过期天数，超过此天数将触发重新查询。 |

## 安全加固

### 1. IP 白名单

建议在 Nginx 层配置 IP 白名单，仅允许受信任的 IP 访问：

```nginx
# nginx/nginx.conf
allow 192.168.1.0/24; # 示例：允许内网访问
allow 203.0.113.50;   # 示例：允许特定公网 IP
deny all;             # 拒绝其他所有访问
```

### 2. 云厂商安全组

在云服务器控制台配置安全组规则，仅开放必要的端口（如 80, 443, 22），并限制来源 IP。

### 3. 启用 HTTPS

生产环境强烈建议配置 SSL 证书并启用 HTTPS，以保护传输中的敏感数据（如 API 密钥）。

## 常用运维命令

```bash
# 构建并启动服务
docker compose up -d --build

# 查看容器运行状态
docker compose ps

# 查看应用日志
docker compose logs -f tirev2-app

# 停止服务
docker compose down

# 重启服务
docker compose restart
```

## 规则热更新

项目中的 `rules/` 目录已通过 Docker 卷挂载到容器中。

1. 修改宿主机上的 `rules/` 目录下的 YAML 文件。
2. 执行以下命令重启应用以加载新规则：

```bash
docker compose restart tirev2-app
```

## 故障排查

如果部署出现问题，请按以下步骤检查：

1. **检查容器状态**: 使用 `docker compose ps` 确认容器是否处于 `Up` 状态。
2. **查看日志**: 使用 `docker compose logs -f` 查看报错信息。
3. **端口占用**: 确保 `TIRE_PORT` 设置的端口未被其他程序占用。

更多详细排查步骤请参考 [故障排查指南](troubleshooting.md)。

## 推荐云服务器配置

| 项目 | 推荐配置 |
| :--- | :--- |
| 厂商 | 阿里云 ECS / 腾讯云 CVM / 华为云 ECS |
| 规格 | 2 核 4G（轻量应用服务器亦可） |
| 系统 | Ubuntu 22.04 LTS |
| 磁盘 | 40G SSD |
| 带宽 | 5 Mbps（内部测试足够） |

## 数据持久化说明

TIRE V2 的核心数据存储在以下文件中，建议通过 Docker Volume 进行持久化备份：

- `storage/results.db`: 存储查询快照和历史结果。
- `cache/cache.db`: 存储 TTL 缓存数据。
- `data/admin.db`: 存储用户信息、API 密钥配置及系统策略。

在 `docker-compose.yml` 中，这些目录通常已配置为挂载卷，请勿随意删除相关卷数据。
