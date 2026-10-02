#!/usr/bin/env python3
"""去重审计：对任意 classical .list 产物或"源组合模拟"做重复域名逐级量化。

用法:
  python3 scripts/audit_dedupe.py custom-us.list custom-direct.list ...
  python3 scripts/audit_dedupe.py --cn-dryrun   # cn 三源合并模拟(需 /tmp/cmp 的源或网络)
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from build_all_rules import dedupe, is_covered, load_custom, norm_domain, parse, fetch

TYPES = ("suffix", "exact", "keyword", "regex", "ip")


def audit(entries, label: str):
    by_type = Counter(t for t, _ in entries)
    suffixes = {v for t, v in entries if t == "suffix"}
    exacts = {v for t, v in entries if t == "exact"}
    keywords = [v for t, v in entries if t == "keyword"]
    regexes = [v for t, v in entries if t == "regex"]
    ips = [v for t, v in entries if t == "ip"]

    exact_dups = [v for v, c in Counter(t + ":" + v for t, v in entries).items() if c > 1]
    suffix_self_covered = sorted(s for s in suffixes if is_covered(s, suffixes))
    exact_covered = sorted(e for e in exacts if e in suffixes or is_covered(e, suffixes))
    kw_overlap = sorted(s for s in suffixes if any(k in s for k in keywords))
    bad_format = sorted(v for v in suffixes | exacts
                        if not v or " " in v or v.startswith(("-", ".")) or "/" in v)
    # CIDR 包含对计数（ip 集用）
    import ipaddress
    overlap_pairs = 0
    nets = []
    for v in ips:
        try:
            nets.append(ipaddress.ip_network(v, strict=False))
        except ValueError:
            bad_format.append("ip:" + v)
    for i, a in enumerate(nets):
        for b in nets[i + 1:]:
            if a.version == b.version and (a.subnet_of(b) or b.subnet_of(a)):
                overlap_pairs += 1

    print(f"== {label} ==")
    print(f"  条目类型分布: {dict(by_type)}  合计 {len(entries)}")
    print(f"  完全重复(同型同值): {len(exact_dups)}")
    print(f"  suffix 被父域覆盖(冗余): {len(suffix_self_covered)}"
          + (f"  样例 {suffix_self_covered[:8]}" if suffix_self_covered else ""))
    print(f"  exact 被 suffix 覆盖(冗余): {len(exact_covered)}")
    print(f"  suffix 与 keyword 语义重叠(仅耗内存,不改语义): {len(kw_overlap)}"
          + (f"  样例 {kw_overlap[:8]}" if kw_overlap else ""))
    if ips:
        print(f"  IP 网段包含对(重叠): {overlap_pairs}")
    print(f"  格式异常: {len(bad_format)}" + (f"  {bad_format[:8]}" if bad_format else ""))
    verdict = "PASS" if not (exact_dups or suffix_self_covered or exact_covered or bad_format) else "FAIL"
    print(f"  判定: {verdict}")
    return verdict == "PASS"


def parse_list_file(path: Path):
    """解析自家 classical list 产物回条目模型。"""
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",", 1)
        t, v = parts[0], parts[1]
        m = {"DOMAIN": "exact", "DOMAIN-SUFFIX": "suffix", "DOMAIN-KEYWORD": "keyword",
             "DOMAIN-REGEX": "regex", "IP-CIDR": "ip"}[t]
        out.append((m, v.strip().lower() if m != "regex" else v))
    return out


def cn_dryrun():
    """cn 三源合并模拟：官方 / felixonmars / YiXuanZX，逐级量化去重。"""
    print("== cn 三源合并 dry-run ==")
    stages = {}
    stages["官方 cn.list"] = parse(fetch(
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.list"), "meta_list")
    stages["felixonmars"] = parse(fetch(
        "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf"), "felix")
    stages["YiXuanZX cn.txt"] = parse(fetch(
        "https://raw.githubusercontent.com/YiXuanZX/rules/main/ruleset/cn.txt"), "yixuan")

    for k, v in stages.items():
        print(f"  {k}: 原始 {len(v)} 条 -> 去重后 {len(set(v))} 条"
              + (f"  [源内完全重复 {len(v)-len(set(v))}]" if len(v) != len(set(v)) else ""))

    merged = [e for v in stages.values() for e in v]
    uniq = list(dict.fromkeys(merged))
    print(f"  三源合计: {len(merged)} -> 跨源去重后 {len(uniq)} (消除 {len(merged)-len(uniq)} 条完全重复)")

    kept = dedupe(uniq)
    kept_set = set(kept)
    removed = [e for e in uniq if e not in kept_set]
    # 分类被删原因
    kept_suf = {v for t, v in kept if t == "suffix"}
    absorbed_by_tld = sum(1 for t, v in removed if t == "suffix" and v.count(".") >= 1 and is_covered(v, {"cn"}))
    covered_other = sum(1 for t, v in removed if t == "suffix" and not is_covered(v, {"cn"}))
    print(f"  suffix 覆盖去重: 再消除 {len(removed)} 条"
          f"  (其中被 '+.cn' 通配吸收 {absorbed_by_tld} 条, 被其他父域吸收 {covered_other} 条)")
    print(f"  最终 cn 集: {len(kept)} 条  (对照: 官方 111224, YiXuanZX 44351, 原始合计 {len(merged)})")
    sample = sorted(v for t, v in removed if t == "suffix")[:10]
    print(f"  被吸收样例: {sample}")
    audit(kept, "cn 合并后产物自审")


def main():
    args = sys.argv[1:]
    ok = True
    if args and args[0] == "--cn-dryrun":
        cn_dryrun()
        return
    if not args:
        print(__doc__)
        sys.exit(2)
    for p in args:
        path = Path(p)
        entries = (parse_list_file(path) if path.suffix == ".list"
                   else load_custom([path.name]))
        ok &= audit(entries, path.name)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
