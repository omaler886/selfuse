from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "rules" / "sources"
DOMAIN_SOURCE = SOURCE_DIR / "monitoring-block-curated.txt"
IP_SOURCE = SOURCE_DIR / "monitoring-block-ip-curated.txt"
DOMAIN_OUTPUT = ROOT / "monitoring-block.txt"
IP_OUTPUT = ROOT / "monitoring-block-ip.txt"
DOMAIN_MRS = ROOT / "monitoring-block.mrs"
IP_MRS = ROOT / "monitoring-block-ip.mrs"

UPSTREAM_DOMAIN_URLS = [
    "https://codeberg.org/CocoaDuck/Snippets/raw/master/MihomoYAML/Source/Addition/AntiAntiFraud.yaml",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.xiaomi-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.huawei-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.oppo-realme-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.vivo-onlydomains.txt",
]

OEM_TELEMETRY_PATTERN = re.compile(
    r"(mistat|metrics?|datacollector|collector|collect|adlog|adxlog|dsplog|"
    r"tracking|tracker|trace|ubacollect|logservice|log-|log\.|stat\.|stats|"
    r"telemetry|analytics|monitor)",
    re.IGNORECASE,
)

DOMAIN_PATTERN = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z0-9-]+$", re.IGNORECASE)


def fetch_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=45) as response:
        if response.status != 200:
            raise RuntimeError(f"Fetch failed: url={url}, status={response.status}")

        return response.read().decode("utf-8", errors="replace")


def normalize_domain(value: str) -> str | None:
    item = value.strip().lower()

    if not item or item.startswith(("#", "!", ";")):
        return None

    if item.startswith("- "):
        item = item[2:].strip()

    if "," in item:
        parts = [part.strip() for part in item.split(",")]
        if parts[0] in {"domain-suffix", "domain"} and len(parts) >= 2:
            item = parts[1]
        else:
            return None

    item = item.removeprefix("||").removeprefix("|").removeprefix(".")
    item = item.removesuffix("^").removesuffix("/")
    item = item.removeprefix("*.").removeprefix("+.")

    if DOMAIN_PATTERN.match(item):
        return item

    return None


def normalize_ipcidr(value: str) -> str | None:
    item = value.strip()

    if not item or item.startswith("#"):
        return None

    if "," in item:
        parts = [part.strip() for part in item.split(",")]
        if parts[0].lower() == "ip-cidr" and len(parts) >= 2:
            item = parts[1]
        else:
            return None

    try:
        return str(ipaddress.ip_network(item, strict=False))
    except ValueError:
        return None


def read_local_domains(path: Path) -> set[str]:
    return {
        domain
        for line in path.read_text(encoding="utf-8").splitlines()
        if (domain := normalize_domain(line))
    }


def read_local_ipcidrs(path: Path) -> set[str]:
    return {
        network
        for line in path.read_text(encoding="utf-8").splitlines()
        if (network := normalize_ipcidr(line))
    }


def read_upstream_domains() -> set[str]:
    domains: set[str] = set()

    for url in UPSTREAM_DOMAIN_URLS:
        content = fetch_text(url)

        for line in content.splitlines():
            domain = normalize_domain(line)

            if not domain:
                continue

            if "AntiAntiFraud.yaml" in url or OEM_TELEMETRY_PATTERN.search(domain):
                domains.add(domain)

    return domains


def write_domain_list(domains: set[str]) -> None:
    lines = [
        "# Public monitoring blocklist for mihomo.",
        "# Auto-generated from curated entries and trusted upstream telemetry lists.",
        *sorted(domains),
    ]
    DOMAIN_OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_ip_list(networks: set[str]) -> None:
    lines = [
        "# Public monitoring IP blocklist for mihomo.",
        "# Auto-generated from curated stable CIDR entries.",
        *sorted(networks),
    ]
    IP_OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def compile_mrs(mihomo: str) -> None:
    DOMAIN_MRS.unlink(missing_ok=True)
    IP_MRS.unlink(missing_ok=True)

    subprocess.run(
        [mihomo, "convert-ruleset", "domain", "text", str(DOMAIN_OUTPUT), str(DOMAIN_MRS)],
        check=True,
    )
    subprocess.run(
        [mihomo, "convert-ruleset", "ipcidr", "text", str(IP_OUTPUT), str(IP_MRS)],
        check=True,
    )


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: update_monitoring_rules.py <mihomo-binary>")

    domains = read_local_domains(DOMAIN_SOURCE) | read_upstream_domains()
    networks = read_local_ipcidrs(IP_SOURCE)

    write_domain_list(domains)
    write_ip_list(networks)
    compile_mrs(sys.argv[1])

    print(f"domains={len(domains)} ips={len(networks)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
