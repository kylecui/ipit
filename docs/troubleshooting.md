# TIRE V2 故障排查

本文档列出 TIRE V2 常见问题及其解决方法。

---

## 1. 应用无法启动

**症状**：服务启动失败，浏览器无法访问。

**排查步骤**：

1. 检查 `.env` 配置是否完整：
   ```bash
   cat .env | grep -v '^#' | grep -v '^$'
   ```

2. 检查 Docker 容器状态：
   ```bash
   docker compose ps
   ```

3. 查看应用日志：
   ```bash
   docker compose logs -f tire
   # 或
   docker compose logs -f tirev2-app
   ```

4. 检查端口占用：
   ```bash
   ss -tlnp | grep 8000
   ```

5. 本地开发时检查依赖是否安装：
   ```bash
   uv pip install -r requirements.txt
   ```

---

## 2. V2 路径访问异常

**症状**：访问 `/v2/` 返回 404 或重定向错误。

**排查步骤**：

1. 确认 `.env` 中设置了 `ROOT_PATH=/v2`
2. 确认 Nginx 代理配置正确保留了 `/v2` 路径前缀
3. 确认登录后重定向 URL 保持 `/v2` 前缀
4. 检查 Nginx 日志：
   ```bash
   docker compose logs nginx
   ```

---

## 3. 某个插件无结果

**症状**：分析结果中某个数据源显示错误或无数据。

**排查步骤**：

1. 管理后台 → **插件管理**：确认该插件已启用
2. 管理后台 → **共享 API 密钥** 或 **我的 API 密钥**：确认已配置有效密钥
3. 检查上游 API 额度是否耗尽（部分 API 有每日/每月限额）
4. 查看分析结果页面的 **数据源状态表**，确认具体错误信息
5. 使用调试接口获取原始数据：
   ```bash
   curl http://localhost:8000/api/v1/debug/sources/<IP>
   ```
6. 确认服务器网络能访问外部 API（防火墙、代理等）

---

## 4. 报告未使用 LLM

**症状**：生成的报告显示"模板"标签而非"AI"标签。

**说明**：这是正常的回退行为。当 LLM 不可用时，系统自动使用模板生成报告。

**如需启用 AI 报告**：

1. 管理后台 → **LLM 设置**：配置 API Key、Model、Base URL
2. 点击 **验证** 测试连接是否成功
3. 检查用户/策略组是否有 LLM 使用权限
4. 若使用共享 LLM，确认管理员已将共享配置分配给当前用户

---

## 5. API 密钥加解密失败

**症状**：已保存的 API 密钥无法使用，日志中出现 Fernet 解密错误。

**原因**：`TIRE_FERNET_KEY` 变更或未设置。

**解决方法**：

1. 确认 `.env` 中 `TIRE_FERNET_KEY` 已设置
2. **关键**：`TIRE_FERNET_KEY` 必须在部署间保持一致。更换 Key 会导致所有已加密存储的密钥无法解密
3. 若已更换 Key，需在管理后台重新配置所有 API 密钥和 LLM 密钥

生成新的 Fernet Key：
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## 6. 用量统计无记录

**症状**：API 用量统计页面显示空数据。

**排查步骤**：

1. 确认已发生过真实的插件或 LLM 调用（首次部署后需至少执行一次分析）
2. 确认当前账号有权查看数据：
   - 管理员：查看全平台统计
   - 普通用户：仅查看个人范围统计
3. 尝试通过 API 检查：
   ```bash
   curl http://localhost:8000/admin/api/usage
   ```

---

## 7. 缓存与过期

**相关配置**：

| 变量 | 作用 | 默认值 |
|---|---|---|
| `CACHE_TTL_HOURS` | API 响应缓存时长 | 24 小时 |
| `RESULT_STALENESS_DAYS` | 查询结果过期天数 | 7 天 |

- 超过 `RESULT_STALENESS_DAYS` 的结果会在下次查询时自动触发重新采集
- 在 Web 界面勾选 **刷新缓存** 可强制跳过缓存重新查询
- CLI 使用 `--refresh` 参数

---

## 8. 社区插件问题

### 上传验证失败

确保插件文件满足：
- 包含一个继承 `TIPlugin` 的类
- 实现了 `metadata` 属性（返回 `PluginMetadata`）
- 实现了 `query` 异步方法

### 运行超时

- 社区插件默认超时 30 秒
- 可在 `config/plugins.yaml` 中为特定插件调整：
  ```yaml
  plugins:
    my_plugin:
      timeout: 60
  ```

### 内存限制

- Linux：默认 512MB 限制（通过 `RLIMIT_AS`）
- Windows：内存限制不强制（已知限制）
- 可在 `config/plugins.yaml` 中调整 `memory_limit_mb`

---

## 获取帮助

1. **日志查看器**：管理后台 → 日志，实时查看系统日志，按级别筛选和搜索
2. **调试接口**：`GET /api/v1/debug/sources/{ip}` 获取各插件的原始返回数据
3. **健康检查**：`GET /healthz` 和 `GET /readyz` 确认服务状态

---

## 相关文档

- [快速上手](quickstart.md)
- [配置参考](configuration.md)
- [部署指南](deployment.md)
- [管理员指南](admin-guide.md)
