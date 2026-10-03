#!/usr/bin/env python3
"""selfuse 全托管规则构建：多源拉取 -> 合并定向规则 -> suffix 覆盖去重 -> mihomo/sing-box 真内核编译。

产物（仓库根目录）:
  <name>.mrs   mihomo rule-provider (domain/ipcidr, 二进制)
  <name>.list  mihomo classical 文本 (classical=True 的集 或 emit_list=True; 含 keyword/regex/ip 全语义)
  <name>.srs   sing-box rule-set (二进制)
  build-report.md 每轮条目数对比

用法:
  python3 scripts/build_all_rules.py                # 全量
  python3 scripts/build_all_rules.py --only cn,ai   # 指定集
环境:
  MIHOMO_BIN / SINGBOX_BIN  内核路径(默认从 PATH 找); 找不到则跳过对应编译并告警
  HTTPS_PROXY               Actions 不需要; 本地调试按需设置
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rules" / "sources" / "rules-upstreams.json"
CUSTOM_DIR = ROOT / "custom"
BUILD_DIR = ROOT / ".rule-build"
CACHE_DIR = BUILD_DIR / "cache"
REPORT = ROOT / "build-report.md"
COUNTS = ROOT / "rules" / "counts.json"

UA = ("Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36")


# ---------------------------------------------------------------- fetch

def fetch(url: str, use_cache: bool = True) -> str:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", url)[-150:]
    cache = CACHE_DIR / safe
    if use_cache and cache.exists() and time.time() - cache.stat().st_mtime < 6 * 3600:
        return cache.read_text(encoding="utf-8", errors="replace")
    last_err = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read().decode("utf-8", errors="replace")
            cache.write_text(data, encoding="utf-8")
            return data
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"下载失败 {url}: {last_err}")


# ---------------------------------------------------------------- parsers
# 统一条目模型: (type, value)  type in suffix/exact/keyword/regex/ip

def norm_domain(v: str) -> str:
    return v.strip().strip(".").lower()

def parse(text: str, kind: str):
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "//", "!", "payload:")):
            continue
        if kind == "yixuan":
            m = re.match(r"-\s*DOMAIN-SUFFIX,(.+?)\s*$", line)
            if m and norm_domain(m.group(1)):
                out.append(("suffix", norm_domain(m.group(1))))
        elif kind == "felix":
            m = re.match(r"server=/([^/]+)/", line)
            if m and norm_domain(m.group(1)):
                out.append(("suffix", norm_domain(m.group(1))))
        elif kind == "meta_list":
            low = line.lower()
            if low.startswith("full:"):
                out.append(("exact", norm_domain(low[5:])))
            elif low.startswith("keyword:"):
                out.append(("keyword", low[8:].strip().strip(".")))
            elif low.startswith("regexp:"):
                out.append(("regex", low[7:]))
            else:
                out.append(("suffix", norm_domain(low.removeprefix("+."))))
        elif kind == "meta_geoip":
            if "/" in line and not line.startswith("#"):
                out.append(("ip", line.split("#")[0].strip()))
        elif kind in ("dw_list", "plain_domain"):
            low = norm_domain(line.removeprefix("+."))
            if low and "/" not in low and " " not in low:
                out.append(("suffix", low))
        elif kind == "plain_cidr":
            v = line.split("#")[0].strip()
            if "/" in v:
                out.append(("ip", v))
        elif kind == "mihomo_payload":
            if line.startswith("- "):
                item = line[2:].strip().strip('"').strip("'")
                low = item.lower()
                if low.startswith("full:"):
                    out.append(("exact", norm_domain(low[5:])))
                elif low.startswith("keyword:"):
                    out.append(("keyword", low[8:].strip().strip(".")))
                elif low.startswith("regexp:"):
                    out.append(("regex", low[7:]))
                elif low.startswith("+."):
                    out.append(("suffix", norm_domain(low[2:])))
                elif norm_domain(low):
                    out.append(("exact", norm_domain(low)))
        elif kind == "surge":
            if line.startswith(("DOMAIN", "IP-CIDR", "IP-CIDR6")):
                parts = [p.strip() for p in line.split(",")]
                t, v = parts[0], parts[1] if len(parts) > 1 else ""
                v = v.split("#")[0].strip()
                if not v:
                    continue
                if t == "DOMAIN":
                    out.append(("exact", norm_domain(v)))
                elif t == "DOMAIN-SUFFIX":
                    out.append(("suffix", norm_domain(v)))
                elif t == "DOMAIN-KEYWORD":
                    out.append(("keyword", v.lower()))
                elif t == "DOMAIN-REGEX":
                    out.append(("regex", v))
                elif t in ("IP-CIDR", "IP-CIDR6"):
                    out.append(("ip", v))
        # 未知 kind 由调用方校验
    return out


def load_custom(files: list[str], kind: str = "domain"):
    out = []
    for f in files:
        p = CUSTOM_DIR / f
        if not p.exists():
            raise FileNotFoundError(f"custom 文件缺失: {p}")
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if kind == "keyword":
                kw = line.lower().strip(".")
                if kw:
                    out.append(("keyword", kw))
            elif "/" in line and re.match(r"^[0-9a-fA-F:.]+/\d+$", line):
                out.append(("ip", line))
            else:
                d = norm_domain(line.removeprefix("+."))
                if d:
                    out.append(("suffix", d))
    return out


# ---------------------------------------------------------------- dedupe

def is_covered(domain: str, suffixes: set[str]) -> bool:
    parts = domain.split(".")
    return any(".".join(parts[i:]) in suffixes for i in range(1, len(parts)))


def dedupe(entries: list[tuple[str, str]]):
    """suffix 覆盖去重: 子域被其他 suffix 覆盖即剔除; exact 被 suffix 覆盖剔除。"""
    suffixes = {v for t, v in entries if t == "suffix"}
    keep, seen = [], set()
    for t, v in entries:
        key = (t, v)
        if key in seen:
            continue
        seen.add(key)
        if t == "suffix":
            if is_covered(v, suffixes):
                continue
        elif t == "exact":
            if v in suffixes or is_covered(v, suffixes):
                continue
        keep.append((t, v))
    return keep


# ---------------------------------------------------------------- emit

def write_classical_list(path: Path, entries, name: str):
    order = {"exact": "DOMAIN", "suffix": "DOMAIN-SUFFIX",
             "keyword": "DOMAIN-KEYWORD", "regex": "DOMAIN-REGEX", "ip": "IP-CIDR"}
    lines = [f"# {name} — classical 全语义 (由 build_all_rules.py 生成, 勿手改)"]
    for t, v in sorted(entries):
        lines.append(f"{order[t]},{v}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_domain_text(path: Path, entries):
    lines = []
    for t, v in sorted(entries):
        if t == "suffix":
            lines.append(f"+.{v}")
        elif t == "exact":
            lines.append(f"full:{v}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_ip_text(path: Path, entries):
    path.write_text("\n".join(sorted(v for t, v in entries if t == "ip")) + "\n", encoding="utf-8")


def write_singbox_json(path: Path, entries, behavior: str):
    if behavior == "ipcidr":
        rules = [{"ip_cidr": sorted(v for t, v in entries if t == "ip")}]
    else:
        # sing-box 同一 rule 对象内多字段是 AND 语义, 每类型拆一个对象才是 OR
        rules = []
        for t, key in (("suffix", "domain_suffix"), ("exact", "domain"),
                       ("keyword", "domain_keyword"), ("regex", "domain_regex")):
            vals = sorted(v for tt, v in entries if tt == t)
            if vals:
                rules.append({key: vals})
        ips = sorted(v for tt, v in entries if tt == "ip")
        if ips:
            rules.append({"ip_cidr": ips})
        if not rules:
            rules = [{}]
    path.write_text(json.dumps({"version": 2, "rules": rules}, ensure_ascii=False),
                    encoding="utf-8")


def run_core(cmd: list[str]) -> bool:
    if shutil.which(cmd[0]) is None and not Path(cmd[0]).exists():
        print(f"  [warn] 内核 {cmd[0]} 不可用, 跳过此步")
        return False
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} 失败:\n{r.stdout}\n{r.stderr}")
    return True


# ---------------------------------------------------------------- main

def build_set(cfg: dict, only: set[str] | None, mihomo: str, singbox: str) -> dict | None:
    name = cfg["name"]
    if only and name not in only:
        return None
    behavior = cfg.get("behavior", "domain")
    kinds = {"meta_list", "meta_geoip", "dw_list", "yixuan", "felix",
             "surge", "plain_domain", "plain_cidr", "mihomo_payload"}
    entries: list[tuple[str, str]] = []
    for src in cfg.get("sources", []):
        if src["kind"] not in kinds:
            raise ValueError(f"{name}: 未知 source kind {src['kind']}")
        entries += parse(fetch(src["url"]), src["kind"])
    cus = cfg.get("custom", {})
    entries += load_custom(cus.get("domain", []), "domain")
    entries += load_custom(cus.get("keyword", []), "keyword")
    entries += load_custom(cus.get("ip", []), "ip")
    entries = dedupe(entries)

    n_total = len(entries)
    lo, hi = cfg.get("bounds", [1, 10 ** 9])
    if not (lo <= n_total <= hi):
        raise RuntimeError(f"{name}: 条目数 {n_total} 超出安全区间 [{lo},{hi}]，疑似上游异常，拒绝产出")

    emit_list = cfg.get("emit_list", cfg.get("classical", False))
    emit_mrs = cfg.get("emit_mrs", True)
    compiled = {"mrs": False, "srs": False}

    if behavior == "ipcidr":
        if emit_list:
            write_classical_list(ROOT / f"{name}.list", entries, name)
        tmp = BUILD_DIR / f"{name}.iplist"
        write_ip_text(tmp, entries)
        jsonf = BUILD_DIR / f"{name}.json"
        write_singbox_json(jsonf, entries, behavior)
        if emit_mrs:
            compiled["mrs"] = run_core([mihomo, "convert-ruleset", "ipcidr", "text",
                                        str(tmp), str(ROOT / f"{name}.mrs")])
        compiled["srs"] = run_core([singbox, "rule-set", "compile", str(jsonf),
                                    "-o", str(ROOT / f"{name}.srs")])
    else:
        has_special = any(t in ("keyword", "regex", "ip") for t, _ in entries)
        if emit_list:
            write_classical_list(ROOT / f"{name}.list", entries, name)
        if emit_mrs and not has_special:
            tmp = BUILD_DIR / f"{name}.domaintext"
            write_domain_text(tmp, entries)
            compiled["mrs"] = run_core([mihomo, "convert-ruleset", "domain", "text",
                                        str(tmp), str(ROOT / f"{name}.mrs")])
        elif emit_mrs and has_special:
            print(f"  [info] {name} 含 keyword/regex/ip, mrs 仅编译 suffix/exact 部分")
            tmp = BUILD_DIR / f"{name}.domaintext"
            write_domain_text(tmp, [(t, v) for t, v in entries if t in ("suffix", "exact")])
            if tmp.read_text(encoding="utf-8").strip():
                compiled["mrs"] = run_core([mihomo, "convert-ruleset", "domain", "text",
                                            str(tmp), str(ROOT / f"{name}.mrs")])
        jsonf = BUILD_DIR / f"{name}.json"
        write_singbox_json(jsonf, entries, behavior)
        compiled["srs"] = run_core([singbox, "rule-set", "compile", str(jsonf),
                                    "-o", str(ROOT / f"{name}.srs")])
    return {"name": name, "entries": n_total, "compiled": compiled}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="逗号分隔的集名，只构建这些")
    ap.add_argument("--no-cache", action="store_true", help="忽略缓存强制重新下载")
    args = ap.parse_args()
    if args.no_cache:
        shutil.rmtree(CACHE_DIR, ignore_errors=True)

    mihomo = __import__("os").environ.get("MIHOMO_BIN", "mihomo")
    singbox = __import__("os").environ.get("SINGBOX_BIN", "sing-box")
    only = set(args.only.split(",")) if args.only else None

    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    old_counts = {}
    if COUNTS.exists():
        old_counts = json.loads(COUNTS.read_text(encoding="utf-8"))

    results, errors = [], []
    for cfg in manifest["sets"]:
        try:
            r = build_set(cfg, only, mihomo, singbox)
            if r:
                results.append(r)
                print(f"[ok] {r['name']}: {r['entries']} 条  mrs={'✓' if r['compiled']['mrs'] else '—'}"
                      f" srs={'✓' if r['compiled']['srs'] else '—'}")
        except Exception as e:  # noqa: BLE001
            errors.append((cfg["name"], str(e)))
            print(f"[FAIL] {cfg['name']}: {e}", file=sys.stderr)

    if only is None:
        lines = ["# build-report", "",
                 f"构建时间: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}", "",
                 "| 规则集 | 条目 | 上轮 | 变化 | mrs | srs |",
                 "|---|---:|---:|---|:-:|:-:|"]
        for r in results:
            prev = old_counts.get(r["name"])
            delta = "new" if prev is None else f"{r['entries'] - prev:+d}"
            if prev is not None and prev and abs(r["entries"] - prev) / prev > 0.05:
                delta += " ⚠️>5%"
            lines.append(f"| {r['name']} | {r['entries']} | {prev or '—'} | {delta} "
                         f"| {'✓' if r['compiled']['mrs'] else '—'} "
                         f"| {'✓' if r['compiled']['srs'] else '—'} |")
        if errors:
            lines += ["", "## 失败", *[f"- {n}: {msg}" for n, msg in errors]]
        REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
        COUNTS.write_text(json.dumps({r["name"]: r["entries"] for r in results},
                                     ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n完成: {len(results)} 成功, {len(errors)} 失败")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
