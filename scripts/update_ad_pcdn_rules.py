from __future__ import annotations

import re
import subprocess
import sys
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "rules" / "sources"

ADS_CN_OUTPUT = ROOT / "ads-cn.txt"
ADS_GLOBAL_OUTPUT = ROOT / "ads-global.txt"
PCDN_OUTPUT = ROOT / "pcdn.txt"

ADS_CN_MRS = ROOT / "ads-cn.mrs"
ADS_GLOBAL_MRS = ROOT / "ads-global.mrs"
PCDN_MRS = ROOT / "pcdn.mrs"

DOMAIN_PATTERN = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z0-9-]+$", re.IGNORECASE)

ADS_CN_URLS = [
    "https://anti-ad.net/easylist.txt",
    "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt",
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
]

ADS_GLOBAL_URLS = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt",
]

PCDN_URLS: list[str] = []


def fetch_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as response:
        if response.status != 200:
            raise RuntimeError(f"Fetch failed: url={url}, status={response.status}")

        return response.read().decode("utf-8", errors="replace")


def normalize_domain(value: str) -> str | None:
    item = value.strip().lower()

    if not item or item.startswith(("#", "!", ";", "[")):
        return None

    if item.startswith("- "):
        item = item[2:].strip()

    if "," in item:
        parts = [part.strip() for part in item.split(",")]
        if parts[0].lower() in {"domain", "domain-suffix"} and len(parts) >= 2:
            item = parts[1]
        else:
            return None

    if item.startswith("address=/") and item.count("/") >= 2:
        item = item.split("/")[1]

    if item.startswith("server=/") and item.count("/") >= 2:
        item = item.split("/")[1]

    if " " in item:
        parts = item.split()
        if len(parts) == 2 and re.match(r"^(0\.0\.0\.0|127\.0\.0\.1|::1)$", parts[0]):
            item = parts[1]
        else:
            return None

    item = item.removeprefix("||").removeprefix("|").removeprefix(".")
    item = item.removesuffix("^").removesuffix("/")
    item = item.removeprefix("*.").removeprefix("+.")

    if DOMAIN_PATTERN.match(item):
        return item

    return None


def read_local(path: Path) -> set[str]:
    if not path.exists():
        return set()

    return {
        domain
        for line in path.read_text(encoding="utf-8").splitlines()
        if (domain := normalize_domain(line))
    }


def read_urls(urls: list[str]) -> set[str]:
    domains: set[str] = set()

    for url in urls:
        for line in fetch_text(url).splitlines():
            if domain := normalize_domain(line):
                domains.add(domain)

    return domains


def write_list(path: Path, title: str, domains: set[str]) -> None:
    lines = [
        title,
        "# Auto-generated from trusted upstream lists and curated additions.",
        *sorted(domains),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def compile_mrs(mihomo: str) -> None:
    for target in [ADS_CN_MRS, ADS_GLOBAL_MRS, PCDN_MRS]:
        target.unlink(missing_ok=True)

    subprocess.run([mihomo, "convert-ruleset", "domain", "text", str(ADS_CN_OUTPUT), str(ADS_CN_MRS)], check=True)
    subprocess.run([mihomo, "convert-ruleset", "domain", "text", str(ADS_GLOBAL_OUTPUT), str(ADS_GLOBAL_MRS)], check=True)
    subprocess.run([mihomo, "convert-ruleset", "domain", "text", str(PCDN_OUTPUT), str(PCDN_MRS)], check=True)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: update_ad_pcdn_rules.py <mihomo-binary>")

    ads_cn = read_local(SOURCE_DIR / "ads-cn-curated.txt") | read_urls(ADS_CN_URLS)
    ads_global = read_local(SOURCE_DIR / "ads-global-curated.txt") | read_urls(ADS_GLOBAL_URLS)
    pcdn = read_local(SOURCE_DIR / "pcdn-curated.txt") | read_urls(PCDN_URLS)

    write_list(ADS_CN_OUTPUT, "# China ad blocklist for mihomo.", ads_cn)
    write_list(ADS_GLOBAL_OUTPUT, "# Global ad blocklist for mihomo.", ads_global)
    write_list(PCDN_OUTPUT, "# PCDN blocklist for mihomo.", pcdn)
    compile_mrs(sys.argv[1])

    print(f"ads_cn={len(ads_cn)} ads_global={len(ads_global)} pcdn={len(pcdn)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
