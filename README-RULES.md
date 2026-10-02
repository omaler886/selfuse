# 全托管规则构建（新增部分）

把主配置 29 个规则集 + 定向规则全部收编进本仓库，每日 Actions 自动构建。
广告类流水线（update_merged_ad_rules.py）保持不动，两套并行。

## 本地调试

```bash
export HTTPS_PROXY=http://127.0.0.1:12306        # 按需
export MIHOMO_BIN=/d/clash-service/mihomo-windows-amd64.exe
python3 scripts/build_all_rules.py --only cn,ai,custom-us
```

## 加定向条目

改 `custom/` 下对应文件（`.domain.txt` 后缀域名 / `.ip.txt` CIDR / `.keyword.txt` 关键词），
push 后 Actions 次日自动重编；急用就手动 workflow_dispatch。
映射关系在 `rules/sources/rules-upstreams.json` 的 `custom` 字段。

## 产物 → 主配置接线（只加不改）

见 `config-integration.md`。liuyisi 的 jp_domain/flow 只有 .mrs 无文本源，
无法合并，保持原 provider 不动。

## gitignore 追加

```
.rule-build/
.rule-build/cache/
```
