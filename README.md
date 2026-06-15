# selfuse rules

## Mihomo MRS 广告规则

| 文件 | 范围 | Raw URL |
| --- | --- | --- |
| `full.mrs` | 全去广告：合并中国、全球、PCDN、监控拦截、Wuming 和 mihomo 官方广告规则 | `https://raw.githubusercontent.com/omaler886/selfuse/main/full.mrs` |
| `lite.mrs` | 轻量去广告：只包含中国广告域名、HTTPDNS 中国广告域名和 PCDN 域名 | `https://raw.githubusercontent.com/omaler886/selfuse/main/lite.mrs` |
| `global.mrs` | 非中国地区广告域名：全球广告来源中减去 lite 范围，避免中国/PCDN 重叠 | `https://raw.githubusercontent.com/omaler886/selfuse/main/global.mrs` |
| `ad-domain.mrs` | 兼容旧配置的 full 别名 | `https://raw.githubusercontent.com/omaler886/selfuse/main/ad-domain.mrs` |
| `ad-ip.mrs` | 广告相关 IP/CIDR 规则 | `https://raw.githubusercontent.com/omaler886/selfuse/main/ad-ip.mrs` |

## 上游来源

完整来源、分支、路径和计数写在 `rules/sources/ad-upstreams.json`。关键上游如下：

| 来源 | 仓库/分支 | 路径或地址 |
| --- | --- | --- |
| `ads-cn` | `omaler886/selfuse@main` | `ads-cn.mrs`，由 anti-AD、privacy-protection-tools/anti-AD、Cats-Team/AdRules 和本仓库精选规则生成 |
| `ads-global` | `omaler886/selfuse@main` | `ads-global.mrs`，由 Hagezi Pro、Hagezi Ultimate 和本仓库精选规则生成 |
| `mihomo-category-ads-all` | `MetaCubeX/meta-rules-dat@meta` | `geo/geosite/category-ads-all.mrs` |
| `httpdns-cn@ads` | `MetaCubeX/meta-rules-dat@meta` | `geo/geosite/category-httpdns-cn@ads.mrs` |
| `wuming-adguard-mobile` | `Wuming155/China-AdGuard-Rules@main` | `dist/adguard_rules_mobile.txt` |
| `wuming-hosts` | `Wuming155/China-AdGuard-Rules@main` | `dist/hosts_rules.txt` |
| `wuming-whitelist` | `Wuming155/China-AdGuard-Rules@main` | `dist/whitelist.txt`，用于从合并结果扣除例外 |
| `pcdn` | `omaler886/selfuse@main` | `pcdn.mrs`，由 `rules/sources/pcdn-curated.txt` 生成 |
| `monitoring-block` | `omaler886/selfuse@main` | `monitoring-block.mrs`，含 CocoaDuck AntiAntiFraud 和本仓库精选规则 |

Wuming155 上游 README 有再分发限制提示；公开托管前应确认使用方式符合上游要求。

## 生成命令

```bash
python3 scripts/update_ad_pcdn_rules.py ./mihomo
python3 scripts/update_merged_ad_rules.py ./mihomo
```

`update_merged_ad_rules.py` 会生成 `full.mrs`、`lite.mrs`、`global.mrs`、`ad-domain.mrs`、`ad-ip.mrs`，并更新 `rules/sources/ad-upstreams.json`。

## Cloudflare Worker

本仓库仍保留私有导航 Worker：密码登录、书签、天气、背景图和 KV 数据。部署前配置 `wrangler.toml` 的 KV Namespace，并设置 `ACCESS_PASSWORD` 与 `SESSION_SECRET`。
