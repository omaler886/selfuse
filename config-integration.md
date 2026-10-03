# 主配置接线片段（只加不改）

产物 URL 基址: `https://raw.githubusercontent.com/omaler886/selfuse/main/`

## 1. 立即可加（阶段 1）—— base cn + 定向集

```yaml
# rule-providers 追加（锚点复用现有 ip/domain/classical）
cn-base: {<<: *domain, url: "https://raw.githubusercontent.com/omaler886/selfuse/main/cn.mrs"}
custom-direct: {<<: *domain, url: "https://raw.githubusercontent.com/omaler886/selfuse/main/custom-direct.mrs"}
custom-direct-ip: {<<: *ip, url: "https://raw.githubusercontent.com/omaler886/selfuse/main/custom-direct-ip.mrs"}
custom-us: {<<: *classical, url: "https://raw.githubusercontent.com/omaler886/selfuse/main/custom-us.list"}
custom-cdn: {<<: *domain, url: "https://raw.githubusercontent.com/omaler886/selfuse/main/custom-cdn.mrs"}
custom-hk: {<<: *domain, url: "https://raw.githubusercontent.com/omaler886/selfuse/main/custom-hk.mrs"}
custom-netflix: {<<: *domain, url: "https://raw.githubusercontent.com/omaler886/selfuse/main/custom-netflix.mrs"}
custom-reject: {<<: *domain, url: "https://raw.githubusercontent.com/omaler886/selfuse/main/custom-reject.mrs"}
```

```yaml
# rules 追加位置（都在现有对应规则旁边，命中顺序等价）
- RULE-SET,custom-reject,REJECT              # ad-domain 之前或并列
- RULE-SET,custom-direct,直连                # 现 DOMAIN 直连规则旁边
- RULE-SET,custom-direct-ip,直连,no-resolve  # 现 IP-CIDR 直连规则旁边
- RULE-SET,custom-us,美国                    # 现 example-us1 等 DOMAIN,美国 规则旁边
- RULE-SET,custom-cdn,cdn                    # gofile 旁边
- RULE-SET,custom-hk,香港                    # example-hk 旁边
- RULE-SET,custom-netflix,netflix            # speedtest 旁边
- RULE-SET,cn-base,直连                      # RULE-SET,cn,直连 之前
```

```yaml
# dns.fake-ip-filter 追加（MATCH,fake-ip 之前）
- RULE-SET,cn-base,real-ip
```

老的写死 DOMAIN/IP-CIDR 规则与新 RULE-SET 并存无冲突（先命中先赢），观察一周无异常后
手动删除老规则行（这步是"改"，你过目执行）。流程照旧：本地改 → 9090 PUT /configs?force=true →
substore sync push --apply。

## 2. 阶段 2——其余 provider 逐个切自托管

对应关系（上游名 → 本仓库产物，一一同名）：

| 主配置 provider | 切换后 URL 指向 |
|---|---|
| private / private-ip / cn_ip / google_ip / telegramip / netflix-ip | 同名 .mrs |
| google / telegram / netflix / spotify / discord / ehentai / onedrive / talkatone / epicgames / ntp | 同名 .mrs |
| cn-game → games-cn / google_cn → google-cn / apple-cn / microsoft-cn / ai / trackerslist | 同名 .mrs |
| cn (YiXuanZX) → cn-base | 已在阶段 1 |
| geolocation-!cn → proxy | proxy.mrs（含 keyword/regex 的全量语义用 proxy.list） |
| jp_domain / flow | 不动（liuyisi 无文本源，无法收编） |

切换 = 改 provider 的 url 字段，属"改"，逐条执行：加新 provider 并存 → 面板确认 → 删旧。

## 3. custom-us 例外说明

含 DOMAIN-KEYWORD（example-keyword/example-keyword2），mihomo 的 mrs 装不下，所以只发 classical
`.list`（custom-us.mrs 不会产出）。行为与现在写死的 DOMAIN-KEYWORD 规则一致。
