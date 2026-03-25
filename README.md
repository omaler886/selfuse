# Cloudflare Worker: 私有导航 + 书签 + 天气

## 功能
- 密码登录后访问（私有页面）
- 导航/书签双视图（数据存储在 KV）
- 天气预报（Open-Meteo）
- 首次载入动画、切换标签页动画
- 高斯模糊玻璃风格 UI
- 背景图支持：KV 手动设置，或每日自动更换

## 部署
1. 创建 KV Namespace，记下 ID。
2. 修改 `wrangler.toml` 中 `kv_namespaces.id`。
3. 配置密钥：
   ```bash
   wrangler secret put ACCESS_PASSWORD
   wrangler secret put SESSION_SECRET
   ```
4. 部署：
   ```bash
   wrangler deploy
   ```

## KV 键说明
- `bookmarks`: 书签数组 JSON
- `bg:manual`: 手动背景 URL（存在则优先）
- `bg:auto:YYYY-MM-DD`: 当日自动背景缓存
