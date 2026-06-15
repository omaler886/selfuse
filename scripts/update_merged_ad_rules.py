from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / ".rule-build"
DOMAIN_OUTPUT = BUILD_DIR / "ad-domain.txt"
IP_OUTPUT = BUILD_DIR / "ad-ipcidr.txt"
DOMAIN_MRS = ROOT / "ad-domain.mrs"
IP_MRS = ROOT / "ad-ip.mrs"
MANIFEST = ROOT / "rules" / "sources" / "ad-upstreams.json"

HTTPDNS_MRS_URL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-httpdns-cn@ads.mrs"
MIHOMO_ADS_ALL_MRS_URL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.mrs"
WUMING_MOBILE_URL = "https://raw.githubusercontent.com/Wuming155/China-AdGuard-Rules/main/dist/adguard_rules_mobile.txt"
WUMING_HOSTS_URL = "https://raw.githubusercontent.com/Wuming155/China-AdGuard-Rules/main/dist/hosts_rules.txt"
WUMING_WHITELIST_URL = "https://raw.githubusercontent.com/Wuming155/China-AdGuard-Rules/main/dist/whitelist.txt"

DOMAIN_PATTERN = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z0-9-]+$", re.IGNORECASE)
ADGUARD_HOST_END_PATTERN = re.compile(r"[\^/:?#\[\]@|]")
URL_HOST_PATTERN = re.compile(r"^\|?https?://([^/:?#]+)", re.IGNORECASE)
BLOCK_HOSTS = {"0.0.0.0", "127.0.0.1", "::1"}


@dataclass(frozen=True)
class Source:
    """Purpose: describe one input for the merged ad rules.

    Args:
        name: Stable input name used for build-cache and manifest entries.
        behavior: Mihomo rule-set behavior, either domain or ipcidr.
        kind: Input kind, such as mrs, adguard-block, hosts-block, or adguard-allow.
        path: Local source path when the input is generated in this repo.
        url: Remote source URL when the input is maintained elsewhere.

    Returns:
        Immutable input metadata for the merge pipeline.
    """

    name: str
    behavior: str
    kind: str
    path: Path | None = None
    url: str | None = None


DOMAIN_SOURCES = (
    Source("ads-cn", "domain", "mrs", path=ROOT / "ads-cn.mrs"),
    Source("ads-global", "domain", "mrs", path=ROOT / "ads-global.mrs"),
    Source("mihomo-category-ads-all", "domain", "mrs", url=MIHOMO_ADS_ALL_MRS_URL),
    Source("wuming-adguard-mobile", "domain", "adguard-block", url=WUMING_MOBILE_URL),
    Source("wuming-hosts", "domain", "hosts-block", url=WUMING_HOSTS_URL),
    Source("monitoring-block", "domain", "mrs", path=ROOT / "monitoring-block.mrs"),
    Source("pcdn", "domain", "mrs", path=ROOT / "pcdn.mrs"),
    Source("httpdns-cn@ads", "domain", "mrs", url=HTTPDNS_MRS_URL),
)

DOMAIN_EXCLUDES = (
    Source("wuming-whitelist", "domain", "adguard-allow", url=WUMING_WHITELIST_URL),
)

IP_SOURCES = (
    Source("monitoring-block-ip", "ipcidr", "mrs", path=ROOT / "monitoring-block-ip.mrs"),
)


def fetch_file(url: str, target: Path) -> None:
    """Purpose: download a remote input.

    Args:
        url: Remote HTTP(S) URL to download.
        target: Local file path that receives the downloaded bytes.

    Returns:
        None.
    """

    request = urllib.request.Request(url, headers={"User-Agent": "github-actions"})
    with urllib.request.urlopen(request, timeout=90) as response:
        if response.status != 200:
            raise RuntimeError(f"Fetch failed: url={url}, status={response.status}")

        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(response.read())


def get_source_path(source: Source) -> Path:
    """Purpose: resolve a local or remote source into a local path.

    Args:
        source: Input metadata with either path or url set.

    Returns:
        Local path containing the source bytes.
    """

    if source.path:
        if not source.path.exists():
            raise FileNotFoundError(f"source not found: {source.path}")

        return source.path

    if not source.url:
        raise ValueError(f"source has neither path nor url: {source.name}")

    suffix = ".mrs" if source.kind == "mrs" else ".txt"
    target = BUILD_DIR / "raw" / f"{source.name}{suffix}"
    fetch_file(source.url, target)
    return target


def convert_ruleset(mihomo: str, behavior: str, input_format: str, source: Path, target: Path) -> None:
    """Purpose: run Mihomo's rule-set converter.

    Args:
        mihomo: Mihomo executable path.
        behavior: Rule-set behavior, such as domain or ipcidr.
        input_format: Source format passed to convert-ruleset.
        source: Source rule file path.
        target: Target rule file path.

    Returns:
        None.
    """

    target.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [mihomo, "convert-ruleset", behavior, input_format, str(source), str(target)],
        check=True,
    )


def expand_source(mihomo: str, source: Source) -> Path:
    """Purpose: expand one source MRS to text.

    Args:
        mihomo: Mihomo executable path.
        source: MRS input metadata.

    Returns:
        Path to the expanded text file.
    """

    if source.kind != "mrs":
        raise ValueError(f"source is not MRS: {source.name}")

    source_path = get_source_path(source)
    target = BUILD_DIR / "expanded" / f"{source.name}.text"
    convert_ruleset(mihomo, source.behavior, "mrs", source_path, target)
    return target


def normalize_domain(value: str) -> str | None:
    """Purpose: normalize a domain-like value into bare-domain form.

    Args:
        value: Raw rule line or candidate domain.

    Returns:
        Lowercase bare domain, or None when the value is not a domain rule.
    """

    item = value.strip().lower().rstrip(".")
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

    item = item.removeprefix("||").removeprefix("|").removeprefix(".")
    item = item.removesuffix("^").removesuffix("/")
    item = item.removeprefix("*.").removeprefix("+.")
    if "*" in item or "/" in item:
        return None

    if DOMAIN_PATTERN.match(item):
        return item

    return None


def normalize_ipcidr(value: str) -> str | None:
    """Purpose: normalize an IP/CIDR rule.

    Args:
        value: Raw rule line from an expanded MRS.

    Returns:
        Canonical CIDR, or None when the line is not an IP rule.
    """

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


def has_badfilter_option(value: str) -> bool:
    """Purpose: detect AdGuard rules that explicitly disable another rule.

    Args:
        value: Raw AdGuard rule line.

    Returns:
        True when the rule has a badfilter option.
    """

    if "$" not in value:
        return False

    options = value.split("$", 1)[1]
    return "badfilter" in {option.strip() for option in options.split(",")}


def normalize_adguard_block_domain(value: str) -> str | None:
    """Purpose: extract a DNS-safe block domain from an AdGuard rule.

    Args:
        value: Raw AdGuard block rule.

    Returns:
        Bare domain when the rule can be represented as a Mihomo domain rule.
    """

    item = value.strip().lower()
    if not item or item.startswith(("#", "!", ";", "[", "@@")):
        return None

    if has_badfilter_option(item):
        return None

    target = item.split("$", 1)[0].strip()
    if target.startswith("||"):
        host = ADGUARD_HOST_END_PATTERN.split(target[2:], 1)[0]
        return normalize_domain(host)

    match = URL_HOST_PATTERN.match(target)
    if match:
        return normalize_domain(match.group(1))

    return None


def normalize_adguard_allow_domain(value: str) -> str | None:
    """Purpose: extract a DNS-safe exception domain from an AdGuard rule.

    Args:
        value: Raw AdGuard allow rule.

    Returns:
        Bare domain when the exception can safely subtract a block rule.
    """

    item = value.strip()
    if not item.startswith("@@"):
        return None

    return normalize_adguard_block_domain(item[2:])


def normalize_hosts_domain(value: str) -> str | None:
    """Purpose: extract a block domain from a hosts-format line.

    Args:
        value: Raw hosts line.

    Returns:
        Bare domain when the hosts entry maps to a blocking address.
    """

    parts = value.strip().lower().split()
    if len(parts) < 2 or parts[0] not in BLOCK_HOSTS:
        return None

    # Hosts wildcards cannot always be represented exactly by MRS domain rules.
    return normalize_domain(parts[1])


def read_rules(path: Path, behavior: str) -> set[str]:
    """Purpose: read normalized rules from expanded MRS text.

    Args:
        path: Expanded text rule file.
        behavior: Rule-set behavior deciding the normalizer.

    Returns:
        Set of normalized rule entries.
    """

    normalizer = normalize_domain if behavior == "domain" else normalize_ipcidr
    rules: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        rule = normalizer(line)
        if rule:
            rules.add(rule)

    return rules


def read_text_rules(path: Path, kind: str) -> set[str]:
    """Purpose: read normalized rules from a supported text input.

    Args:
        path: Text source file path.
        kind: Text source kind deciding which parser is used.

    Returns:
        Set of normalized domain rules.
    """

    normalizers = {
        "adguard-block": normalize_adguard_block_domain,
        "adguard-allow": normalize_adguard_allow_domain,
        "hosts-block": normalize_hosts_domain,
    }
    normalizer = normalizers.get(kind)
    if not normalizer:
        raise ValueError(f"unsupported text source kind: {kind}")

    return {
        rule
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if (rule := normalizer(line))
    }


def read_source_rules(mihomo: str, source: Source) -> set[str]:
    """Purpose: normalize rules from any supported source kind.

    Args:
        mihomo: Mihomo executable path for MRS expansion.
        source: Source metadata describing the input.

    Returns:
        Set of normalized rules from the source.
    """

    if source.kind == "mrs":
        return read_rules(expand_source(mihomo, source), source.behavior)

    if source.behavior != "domain":
        raise ValueError(f"text source must be domain behavior: {source.name}")

    return read_text_rules(get_source_path(source), source.kind)


def write_rules(path: Path, title: str, rules: set[str]) -> None:
    """Purpose: write merged text rules for compilation.

    Args:
        path: Text output path.
        title: Comment title written to the first line.
        rules: Normalized rules to write.

    Returns:
        None.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        title,
        "# Auto-generated from expanded MRS inputs and supported text upstreams.",
        *sorted(rules),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build(
    mihomo: str,
    sources: tuple[Source, ...],
    text_output: Path,
    mrs_output: Path,
    exclude_sources: tuple[Source, ...] = (),
) -> dict[str, int]:
    """Purpose: expand, deduplicate, write, and compile one merged rule-set.

    Args:
        mihomo: Mihomo executable path.
        sources: Inputs sharing the same behavior.
        text_output: Temporary merged text rule output.
        mrs_output: Final compiled MRS output.
        exclude_sources: Domain exception sources to subtract before compiling.

    Returns:
        Per-source counts plus merged and excluded counts.
    """

    behavior = sources[0].behavior
    merged_rules: set[str] = set()
    counts: dict[str, int] = {}
    for source in sources:
        rules = read_source_rules(mihomo, source)
        counts[source.name] = len(rules)
        merged_rules.update(rules)

    excluded_rules: set[str] = set()
    for source in exclude_sources:
        rules = read_source_rules(mihomo, source)
        counts[f"exclude:{source.name}"] = len(rules)
        excluded_rules.update(rules)

    merged_rules.difference_update(excluded_rules)
    counts["excluded"] = len(excluded_rules)
    write_rules(text_output, f"# Merged {behavior} ad blocklist for mihomo.", merged_rules)
    convert_ruleset(mihomo, behavior, "text", text_output, mrs_output)
    counts["merged"] = len(merged_rules)
    return counts


def format_source(source: Source) -> dict[str, str | None]:
    """Purpose: convert source metadata into JSON-safe manifest data.

    Args:
        source: Input metadata to serialize.

    Returns:
        Manifest-ready mapping for one source.
    """

    path = None
    if source.path:
        path = str(source.path.relative_to(ROOT)).replace("\\", "/")

    return {
        "name": source.name,
        "behavior": source.behavior,
        "kind": source.kind,
        "path": path,
        "url": source.url,
    }


def write_manifest(domain_counts: dict[str, int], ip_counts: dict[str, int]) -> None:
    """Purpose: persist source URLs and rule counts for auditability.

    Args:
        domain_counts: Per-source and merged domain counts.
        ip_counts: Per-source and merged IP/CIDR counts.

    Returns:
        None.
    """

    data = {
        "domainMrs": str(DOMAIN_MRS.relative_to(ROOT)).replace("\\", "/"),
        "ipMrs": str(IP_MRS.relative_to(ROOT)).replace("\\", "/"),
        "domainCounts": domain_counts,
        "ipCounts": ip_counts,
        "domainSources": [format_source(source) for source in DOMAIN_SOURCES],
        "domainExcludes": [format_source(source) for source in DOMAIN_EXCLUDES],
        "ipSources": [format_source(source) for source in IP_SOURCES],
        "sourceNotes": {
            "wuming155": "Upstream README states no redistribution; verify permission before public publishing.",
        },
    }
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(data, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    """Purpose: update merged ad-domain and ad-ip MRS outputs.

    Args:
        None.

    Returns:
        Process exit code.
    """

    if len(sys.argv) != 2:
        raise SystemExit("Usage: update_merged_ad_rules.py <mihomo-binary>")

    domain_counts = build(sys.argv[1], DOMAIN_SOURCES, DOMAIN_OUTPUT, DOMAIN_MRS, DOMAIN_EXCLUDES)
    ip_counts = build(sys.argv[1], IP_SOURCES, IP_OUTPUT, IP_MRS)
    write_manifest(domain_counts, ip_counts)
    print(f"domain={domain_counts['merged']} ipcidr={ip_counts['merged']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
