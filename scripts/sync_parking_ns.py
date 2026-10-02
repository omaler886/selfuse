#!/usr/bin/env python3
"""同步停放商 NS 后缀库（源：MISP warninglists / parking-domain-ns）。

设计要点：
- 同步失败时**保留仓库内静态副本**，绝不阻断扫描（exit 0）。
- 同步结果条数异常（< 50）时拒绝覆盖，防上游变更/网络中间页污染。
- 白名单剔除建站托管商：它们出现在 MISP 列表里，但是托管商不是停放商，
  直接匹配会误杀大量正常站（实测 wordpress.com / one.com）。
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

URL = "https://misp.github.io/misp-warninglists/lists/parking-domain-ns/list.json"
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "parking-ns.txt"
ALLOW = {"wordpress.com", "one.com"}   # 建站托管商，非停放商 —— 误杀源，必须剔除
MIN_ENTRIES = 50                       # 低于此数视为同步异常，拒绝覆盖


def main() -> int:
    try:
        req = urllib.request.Request(
            URL, headers={"User-Agent": "selfuse-parking-ns-sync/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            obj = json.loads(r.read().decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        print(f"warn: MISP 同步失败，沿用仓库内静态副本（{e}）", file=sys.stderr)
        return 0

    raw = obj.get("list") or []
    lst = sorted({x.strip().lower().rstrip(".") for x in raw if x.strip()})
    out = [x for x in lst if x not in ALLOW]
    if len(out) < MIN_ENTRIES:
        print(f"warn: 同步结果异常（{len(out)} 条 < {MIN_ENTRIES}），拒绝覆盖", file=sys.stderr)
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        "# 停放商 NS 后缀库 —— 源: MISP misp-warninglists/lists/parking-domain-ns\n"
        f"# version {obj.get('version')} | 原始 {len(raw)} 条 -> 去重 {len(lst)} 条"
        f" -> 白名单剔除 {len(lst) - len(out)} 条 -> {len(out)} 条\n"
        "# 白名单（建站托管商，非停放商，勿匹配）: " + ", ".join(sorted(ALLOW)) + "\n"
        + "\n".join(out) + "\n",
        encoding="utf-8", newline="\n")
    print(f"parking-ns synced: {len(out)} 条 (version {obj.get('version')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
