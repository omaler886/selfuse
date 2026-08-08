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
MANIFEST = ROOT / "rules" / "sources" / "ad-upstreams.json"

FULL_OUTPUT = BUILD_DIR / "full.txt"
LITE_OUTPUT = BUILD_DIR / "lite.txt"
GLOBAL_OUTPUT = BUILD_DIR / "global.txt"
IP_OUTPUT = BUILD_DIR / "ad-ipcidr.txt"

FULL_MRS = ROOT / "full.mrs"
LITE_MRS = ROOT / "lite.mrs"
GLOBAL_MRS = ROOT / "global.mrs"
LEGACY_DOMAIN_MRS = ROOT / "ad-domain.mrs"
IP_MRS = ROOT / "ad-ip.mrs"

SING_BOX_RULE_SET_DIR = ROOT / "sing-box" / "rule-set"
SING_BOX_SOURCE_DIR = BUILD_DIR / "sing-box-source"
FULL_SRS = SING_BOX_RULE_SET_DIR / "full.srs"
LITE_SRS = SING_BOX_RULE_SET_DIR / "lite.srs"
GLOBAL_SRS = SING_BOX_RULE_SET_DIR / "global.srs"

SELFUSE_RAW = "https://raw.githubusercontent.com/omaler886/selfuse/main"
METACUBEX_RAW = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta"
WUMING_RAW = "https://raw.githubusercontent.com/Wuming155/AdGuard-Rules/main"

HTTPDNS_MRS_URL = f"{METACUBEX_RAW}/geo/geosite/category-httpdns-cn@ads.mrs"
MIHOMO_ADS_ALL_MRS_URL = f"{METACUBEX_RAW}/geo/geosite/category-ads-all.mrs"
WUMING_LITE_URL = f"{WUMING_RAW}/dist/adguard_lite.txt"
WUMING_HOSTS_URL = f"{WUMING_RAW}/dist/hosts_rules.txt"
WUMING_WHITELIST_URL = f"{WUMING_RAW}/dist/whitelist.txt"

DOMAIN_PATTERN = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z0-9-]+$", re.IGNORECASE)
ADGUARD_HOST_END_PATTERN = re.compile(r"[\^/:?#\[\]@|]")
URL_HOST_PATTERN = re.compile(r"^\|?https?://([^/:?#]+)", re.IGNORECASE)
BLOCK_HOSTS = {"0.0.0.0", "127.0.0.1", "::1"}
BUSINESS_DOMAIN_EXCLUDES = {
    "a-api.anthropic.com",
    "a-cdn.anthropic.com",
    "anime-tracker.aruku.kro.kr",
    "contoso-my.sharepoint.com",
    "epicgames.com",
    "s.gofile.io",
    "speed.cloudflare.com",
}


@dataclass(frozen=True)
class Upstream:
    """Purpose: describe the branch-level origin for one upstream input.

    Args:
        name: Human-readable upstream name.
        url: Raw upstream URL.
        repository: Repository owner/name, when the source is git-backed.
        branch: Branch or ref name used by the raw URL.
        path: File path inside the upstream repository.
        note: Short explanation for generated or branchless inputs.

    Returns:
        Immutable upstream metadata for manifest output.
    """

    name: str
    url: str
    repository: str | None = None
    branch: str | None = None
    path: str | None = None
    note: str | None = None


@dataclass(frozen=True)
class Source:
    """Purpose: describe one normalized input for ad rule builds.

    Args:
        name: Stable source name used for cache and manifest entries.
        behavior: Mihomo rule-set behavior, either domain or ipcidr.
        kind: Input kind, such as mrs, adguard-block, hosts-block, or adguard-allow.
        region: Logical grouping used by full/lite/global outputs.
        path: Local source path when this repo already generated the input.
        url: Remote raw URL for fetching or audit.
        repository: Repository owner/name for the direct source file.
        branch: Branch or ref name for the direct source file.
        source_path: File path in the direct source repository.
        upstreams: Original upstreams used to create or publish this source.
        note: Short source-specific processing note.

    Returns:
        Immutable source metadata and parser configuration.
    """

    name: str
    behavior: str
    kind: str
    region: str
    path: Path | None = None
    url: str | None = None
    repository: str | None = None
    branch: str | None = None
    source_path: str | None = None
    upstreams: tuple[Upstream, ...] = ()
    note: str | None = None


@dataclass(frozen=True)
class DomainTarget:
    """Purpose: describe one generated domain MRS target.

    Args:
        name: Public target name, such as full, lite, or global.
        description: Human-readable target scope.
        sources: Source inputs merged into this target.
        excludes: Exception inputs subtracted from this target.
        subtract_sources: Source inputs subtracted to enforce target scope.
        text_output: Temporary text rule output path.
        mrs_output: Public compiled MRS path.
        srs_output: Public compiled sing-box SRS path.
        mrs_aliases: Additional compiled MRS paths with identical bytes.
        text_aliases: Additional text paths with identical rules.

    Returns:
        Immutable target build plan.
    """

    name: str
    description: str
    sources: tuple[Source, ...]
    excludes: tuple[Source, ...]
    subtract_sources: tuple[Source, ...]
    text_output: Path
    mrs_output: Path
    srs_output: Path
    mrs_aliases: tuple[Path, ...] = ()
    text_aliases: tuple[Path, ...] = ()


ANTI_AD_EASYLIST = Upstream(
    name="anti-AD EasyList",
    url="https://anti-ad.net/easylist.txt",
    note="Branchless upstream HTTP endpoint.",
)
CATS_ADRULES_DNS = Upstream(
    name="Cats-Team AdRules DNS",
    url="https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
    repository="Cats-Team/AdRules",
    branch="main",
    path="dns.txt",
)
PRIVACY_ANTI_AD = Upstream(
    name="privacy-protection-tools anti-AD domains",
    url="https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt",
    repository="privacy-protection-tools/anti-AD",
    branch="master",
    path="anti-ad-domains.txt",
)
HAGEZI_PRO = Upstream(
    name="Hagezi Pro only-domains",
    url="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
    repository="hagezi/dns-blocklists",
    branch="main",
    path="wildcard/pro-onlydomains.txt",
)
HAGEZI_ULTIMATE = Upstream(
    name="Hagezi Ultimate only-domains",
    url="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt",
    repository="hagezi/dns-blocklists",
    branch="main",
    path="wildcard/ultimate-onlydomains.txt",
)

ADS_CN_SOURCE = Source(
    name="ads-cn",
    behavior="domain",
    kind="mrs",
    region="china",
    path=ROOT / "ads-cn.mrs",
    url=f"{SELFUSE_RAW}/ads-cn.mrs",
    repository="omaler886/selfuse",
    branch="main",
    source_path="ads-cn.mrs",
    upstreams=(
        ANTI_AD_EASYLIST,
        PRIVACY_ANTI_AD,
        CATS_ADRULES_DNS,
        Upstream(
            name="selfuse curated China ads",
            url=f"{SELFUSE_RAW}/rules/sources/ads-cn-curated.txt",
            repository="omaler886/selfuse",
            branch="main",
            path="rules/sources/ads-cn-curated.txt",
        ),
    ),
)
ADS_GLOBAL_SOURCE = Source(
    name="ads-global",
    behavior="domain",
    kind="mrs",
    region="global",
    path=ROOT / "ads-global.mrs",
    url=f"{SELFUSE_RAW}/ads-global.mrs",
    repository="omaler886/selfuse",
    branch="main",
    source_path="ads-global.mrs",
    upstreams=(
        HAGEZI_PRO,
        HAGEZI_ULTIMATE,
        Upstream(
            name="selfuse curated global ads",
            url=f"{SELFUSE_RAW}/rules/sources/ads-global-curated.txt",
            repository="omaler886/selfuse",
            branch="main",
            path="rules/sources/ads-global-curated.txt",
        ),
    ),
)
MIHOMO_ADS_ALL_SOURCE = Source(
    name="mihomo-category-ads-all",
    behavior="domain",
    kind="mrs",
    region="global",
    url=MIHOMO_ADS_ALL_MRS_URL,
    repository="MetaCubeX/meta-rules-dat",
    branch="meta",
    source_path="geo/geosite/category-ads-all.mrs",
    upstreams=(
        Upstream(
            name="mihomo official category-ads-all MRS",
            url=MIHOMO_ADS_ALL_MRS_URL,
            repository="MetaCubeX/meta-rules-dat",
            branch="meta",
            path="geo/geosite/category-ads-all.mrs",
        ),
    ),
)
WUMING_LITE_SOURCE = Source(
    name="wuming-adguard-lite",
    behavior="domain",
    kind="adguard-block",
    region="china",
    url=WUMING_LITE_URL,
    repository="Wuming155/AdGuard-Rules",
    branch="main",
    source_path="dist/adguard_lite.txt",
    upstreams=(
        Upstream(
            name="Wuming155 AdGuard lite rules",
            url=WUMING_LITE_URL,
            repository="Wuming155/AdGuard-Rules",
            branch="main",
            path="dist/adguard_lite.txt",
        ),
    ),
    note="Only DNS-safe block rules are imported; cosmetic and scoped network rules are ignored.",
)
WUMING_HOSTS_SOURCE = Source(
    name="wuming-hosts",
    behavior="domain",
    kind="hosts-block",
    region="china",
    url=WUMING_HOSTS_URL,
    repository="Wuming155/AdGuard-Rules",
    branch="main",
    source_path="dist/hosts_rules.txt",
    upstreams=(
        Upstream(
            name="Wuming155 hosts rules",
            url=WUMING_HOSTS_URL,
            repository="Wuming155/AdGuard-Rules",
            branch="main",
            path="dist/hosts_rules.txt",
        ),
    ),
)
MONITORING_SOURCE = Source(
    name="monitoring-block",
    behavior="domain",
    kind="mrs",
    region="china",
    path=ROOT / "monitoring-block.mrs",
    url=f"{SELFUSE_RAW}/monitoring-block.mrs",
    repository="omaler886/selfuse",
    branch="main",
    source_path="monitoring-block.mrs",
    upstreams=(
        Upstream(
            name="CocoaDuck AntiAntiFraud",
            url="https://codeberg.org/CocoaDuck/Snippets/raw/master/MihomoYAML/Source/Addition/AntiAntiFraud.yaml",
            repository="CocoaDuck/Snippets",
            branch="master",
            path="MihomoYAML/Source/Addition/AntiAntiFraud.yaml",
        ),
        Upstream(
            name="selfuse curated monitoring blocklist",
            url=f"{SELFUSE_RAW}/rules/sources/monitoring-block-curated.txt",
            repository="omaler886/selfuse",
            branch="main",
            path="rules/sources/monitoring-block-curated.txt",
        ),
    ),
)
PCDN_SOURCE = Source(
    name="pcdn",
    behavior="domain",
    kind="mrs",
    region="pcdn",
    path=ROOT / "pcdn.mrs",
    url=f"{SELFUSE_RAW}/pcdn.mrs",
    repository="omaler886/selfuse",
    branch="main",
    source_path="pcdn.mrs",
    upstreams=(
        Upstream(
            name="selfuse curated PCDN domains",
            url=f"{SELFUSE_RAW}/rules/sources/pcdn-curated.txt",
            repository="omaler886/selfuse",
            branch="main",
            path="rules/sources/pcdn-curated.txt",
        ),
    ),
)
HTTPDNS_SOURCE = Source(
    name="httpdns-cn@ads",
    behavior="domain",
    kind="mrs",
    region="china",
    url=HTTPDNS_MRS_URL,
    repository="MetaCubeX/meta-rules-dat",
    branch="meta",
    source_path="geo/geosite/category-httpdns-cn@ads.mrs",
    upstreams=(
        Upstream(
            name="mihomo official category-httpdns-cn@ads list",
            url=f"{METACUBEX_RAW}/geo/geosite/category-httpdns-cn@ads.list",
            repository="MetaCubeX/meta-rules-dat",
            branch="meta",
            path="geo/geosite/category-httpdns-cn@ads.list",
        ),
    ),
)
WUMING_WHITELIST_SOURCE = Source(
    name="wuming-whitelist",
    behavior="domain",
    kind="adguard-allow",
    region="china",
    url=WUMING_WHITELIST_URL,
    repository="Wuming155/AdGuard-Rules",
    branch="main",
    source_path="dist/whitelist.txt",
    upstreams=(
        Upstream(
            name="Wuming155 whitelist",
            url=WUMING_WHITELIST_URL,
            repository="Wuming155/AdGuard-Rules",
            branch="main",
            path="dist/whitelist.txt",
        ),
    ),
    note="Only DNS-safe @@ exceptions are used to subtract block domains.",
)
MONITORING_IP_SOURCE = Source(
    name="monitoring-block-ip",
    behavior="ipcidr",
    kind="mrs",
    region="china",
    path=ROOT / "monitoring-block-ip.mrs",
    url=f"{SELFUSE_RAW}/monitoring-block-ip.mrs",
    repository="omaler886/selfuse",
    branch="main",
    source_path="monitoring-block-ip.mrs",
    upstreams=(
        Upstream(
            name="selfuse curated monitoring IP blocklist",
            url=f"{SELFUSE_RAW}/rules/sources/monitoring-block-ip-curated.txt",
            repository="omaler886/selfuse",
            branch="main",
            path="rules/sources/monitoring-block-ip-curated.txt",
        ),
    ),
)

FULL_SOURCES = (
    ADS_CN_SOURCE,
    ADS_GLOBAL_SOURCE,
    MIHOMO_ADS_ALL_SOURCE,
    WUMING_LITE_SOURCE,
    WUMING_HOSTS_SOURCE,
    MONITORING_SOURCE,
    PCDN_SOURCE,
    HTTPDNS_SOURCE,
)
LITE_SOURCES = (
    ADS_CN_SOURCE,
    WUMING_LITE_SOURCE,
    WUMING_HOSTS_SOURCE,
    PCDN_SOURCE,
    HTTPDNS_SOURCE,
)
GLOBAL_SOURCES = (
    ADS_GLOBAL_SOURCE,
    MIHOMO_ADS_ALL_SOURCE,
)
DOMAIN_EXCLUDES = (WUMING_WHITELIST_SOURCE,)
IP_SOURCES = (MONITORING_IP_SOURCE,)
ALL_SOURCES = (
    ADS_CN_SOURCE,
    ADS_GLOBAL_SOURCE,
    MIHOMO_ADS_ALL_SOURCE,
    WUMING_LITE_SOURCE,
    WUMING_HOSTS_SOURCE,
    MONITORING_SOURCE,
    PCDN_SOURCE,
    HTTPDNS_SOURCE,
    WUMING_WHITELIST_SOURCE,
    MONITORING_IP_SOURCE,
)

DOMAIN_TARGETS = (
    DomainTarget(
        name="full",
        description="All ad-blocking domain rules, including China, global, PCDN, monitoring, Wuming, and mihomo official ads.",
        sources=FULL_SOURCES,
        excludes=DOMAIN_EXCLUDES,
        subtract_sources=(),
        text_output=FULL_OUTPUT,
        mrs_output=FULL_MRS,
        srs_output=FULL_SRS,
        mrs_aliases=(LEGACY_DOMAIN_MRS,),
    ),
    DomainTarget(
        name="lite",
        description="China ad-blocking domains plus PCDN domains only.",
        sources=LITE_SOURCES,
        excludes=DOMAIN_EXCLUDES,
        subtract_sources=(),
        text_output=LITE_OUTPUT,
        mrs_output=LITE_MRS,
        srs_output=LITE_SRS,
    ),
    DomainTarget(
        name="global",
        description="Non-China ad domains from global sources; China and PCDN sources are subtracted.",
        sources=GLOBAL_SOURCES,
        excludes=DOMAIN_EXCLUDES,
        subtract_sources=LITE_SOURCES,
        text_output=GLOBAL_OUTPUT,
        mrs_output=GLOBAL_MRS,
        srs_output=GLOBAL_SRS,
    ),
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


def fetch_file_with_cache(url: str, target: Path) -> None:
    """Purpose: download a remote input while preserving usable cached data.

    Args:
        url: Remote HTTP(S) URL to download.
        target: Local cache path for downloaded bytes.

    Returns:
        None.
    """

    try:
        fetch_file(url, target)
        return
    except Exception:
        if target.exists():
            return

        raise


def get_source_path(source: Source) -> Path:
    """Purpose: resolve a local or remote source into a local path.

    Args:
        source: Input metadata with path or url set.

    Returns:
        Local path containing the source bytes.
    """

    if source.path and source.path.exists():
        return source.path

    if not source.url:
        raise FileNotFoundError(f"source not found and has no URL: {source.name}")

    suffix = ".mrs" if source.kind == "mrs" else ".txt"
    target = BUILD_DIR / "raw" / f"{source.name}{suffix}"
    fetch_file_with_cache(source.url, target)
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

    if "$" in item:
        return None

    target = item.split("$", 1)[0].strip()
    if target.startswith("||"):
        body = target[2:]
        host = ADGUARD_HOST_END_PATTERN.split(body, 1)[0]
        suffix = body[len(host):]
        if suffix not in {"", "^"}:
            return None
        return normalize_domain(host)

    match = URL_HOST_PATTERN.match(target)
    if match:
        if target[match.end():]:
            return None
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


def read_expanded_rules(path: Path, behavior: str) -> set[str]:
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


def read_source_rules(mihomo: str, source: Source, cache: dict[str, set[str]]) -> set[str]:
    """Purpose: normalize rules from any supported source kind with caching.

    Args:
        mihomo: Mihomo executable path for MRS expansion.
        source: Source metadata describing the input.
        cache: Mutable cache keyed by source name.

    Returns:
        Cached set of normalized rules from the source.
    """

    if source.name in cache:
        return cache[source.name]

    if source.kind == "mrs":
        rules = read_expanded_rules(expand_source(mihomo, source), source.behavior)
    elif source.behavior == "domain":
        rules = read_text_rules(get_source_path(source), source.kind)
    else:
        raise ValueError(f"text source must be domain behavior: {source.name}")

    cache[source.name] = rules
    return rules


def collect_rules(
    mihomo: str,
    sources: tuple[Source, ...],
    cache: dict[str, set[str]],
    count_prefix: str = "",
) -> tuple[set[str], dict[str, int]]:
    """Purpose: collect and count normalized rules from several sources.

    Args:
        mihomo: Mihomo executable path.
        sources: Sources to read and merge.
        cache: Mutable source rule cache.
        count_prefix: Prefix applied to count keys.

    Returns:
        Merged rules and per-source counts.
    """

    merged_rules: set[str] = set()
    counts: dict[str, int] = {}
    for source in sources:
        rules = read_source_rules(mihomo, source, cache)
        counts[f"{count_prefix}{source.name}"] = len(rules)
        merged_rules.update(rules)

    return merged_rules, counts


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


def write_sing_box_source(path: Path, rules: set[str]) -> None:
    """Purpose: write sing-box source JSON for domain suffix rules.

    Args:
        path: Source JSON path consumed by sing-box rule-set compile.
        rules: Normalized domain rules to write as suffix matches.

    Returns:
        None.
    """

    if not rules:
        raise ValueError(f"refusing to write empty sing-box source: {path}")

    data = {
        "version": 2,
        "rules": [
            {
                "domain_suffix": sorted(rules),
            }
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def compile_srs(sing_box: str, source: Path, target: Path) -> None:
    """Purpose: compile a sing-box source JSON file to binary SRS.

    Args:
        sing_box: sing-box executable path.
        source: Source JSON rule-set path.
        target: Binary SRS output path.

    Returns:
        None.
    """

    target.parent.mkdir(parents=True, exist_ok=True)
    target.unlink(missing_ok=True)
    subprocess.run(
        [sing_box, "rule-set", "compile", str(source), "-o", str(target)],
        check=True,
    )


def copy_outputs(source: Path, aliases: tuple[Path, ...]) -> None:
    """Purpose: copy one generated output to compatibility aliases.

    Args:
        source: Generated source output path.
        aliases: Alias paths that should contain identical bytes.

    Returns:
        None.
    """

    data = source.read_bytes()
    for alias in aliases:
        alias.parent.mkdir(parents=True, exist_ok=True)
        alias.write_bytes(data)


def build_domain_target(mihomo: str, sing_box: str, target: DomainTarget, cache: dict[str, set[str]]) -> dict[str, int]:
    """Purpose: build one domain target and return its rule counts.

    Args:
        mihomo: Mihomo executable path.
        sing_box: sing-box executable path.
        target: Domain target build plan.
        cache: Mutable source rule cache.

    Returns:
        Count mapping for the target.
    """

    rules, counts = collect_rules(mihomo, target.sources, cache)
    excluded, exclude_counts = collect_rules(mihomo, target.excludes, cache, "exclude:")
    subtracted, subtract_counts = collect_rules(mihomo, target.subtract_sources, cache, "subtract:")
    counts.update(exclude_counts)
    counts.update(subtract_counts)

    removed_rules = excluded | subtracted
    removed_rules.update(BUSINESS_DOMAIN_EXCLUDES)
    rules.difference_update(removed_rules)
    counts["excluded"] = len(removed_rules)
    counts["merged"] = len(rules)

    write_rules(target.text_output, f"# {target.name} ad blocklist for mihomo.", rules)
    copy_outputs(target.text_output, target.text_aliases)
    convert_ruleset(mihomo, "domain", "text", target.text_output, target.mrs_output)
    copy_outputs(target.mrs_output, target.mrs_aliases)
    source_json = SING_BOX_SOURCE_DIR / f"{target.name}.json"
    write_sing_box_source(source_json, rules)
    compile_srs(sing_box, source_json, target.srs_output)
    return counts


def build_ip_rules(mihomo: str, cache: dict[str, set[str]]) -> dict[str, int]:
    """Purpose: build the IP/CIDR ad-related rule output.

    Args:
        mihomo: Mihomo executable path.
        cache: Mutable source rule cache.

    Returns:
        Count mapping for IP/CIDR sources and merged output.
    """

    rules, counts = collect_rules(mihomo, IP_SOURCES, cache)
    counts["merged"] = len(rules)
    write_rules(IP_OUTPUT, "# IP/CIDR ad blocklist for mihomo.", rules)
    convert_ruleset(mihomo, "ipcidr", "text", IP_OUTPUT, IP_MRS)
    return counts


def relative_path(path: Path) -> str:
    """Purpose: format a repository-relative path for the manifest.

    Args:
        path: Absolute path inside the repository.

    Returns:
        POSIX-style repository-relative path.
    """

    return str(path.relative_to(ROOT)).replace("\\", "/")


def format_upstream(upstream: Upstream) -> dict[str, str | None]:
    """Purpose: serialize upstream branch metadata for the manifest.

    Args:
        upstream: Upstream metadata.

    Returns:
        JSON-safe upstream mapping.
    """

    return {
        "name": upstream.name,
        "repository": upstream.repository,
        "branch": upstream.branch,
        "path": upstream.path,
        "rawUrl": upstream.url,
        "note": upstream.note,
    }


def format_source(source: Source) -> dict[str, object]:
    """Purpose: serialize source metadata for the manifest.

    Args:
        source: Source metadata.

    Returns:
        JSON-safe source mapping.
    """

    local_path = relative_path(source.path) if source.path else None
    return {
        "name": source.name,
        "behavior": source.behavior,
        "kind": source.kind,
        "region": source.region,
        "repository": source.repository,
        "branch": source.branch,
        "path": source.source_path,
        "localPath": local_path,
        "rawUrl": source.url,
        "note": source.note,
        "upstreams": [format_upstream(upstream) for upstream in source.upstreams],
    }


def format_target(target: DomainTarget, counts: dict[str, int]) -> dict[str, object]:
    """Purpose: serialize generated target metadata for the manifest.

    Args:
        target: Domain target build plan.
        counts: Rule counts produced while building the target.

    Returns:
        JSON-safe target mapping.
    """

    return {
        "description": target.description,
        "mrs": relative_path(target.mrs_output),
        "srs": relative_path(target.srs_output),
        "rawSrsUrl": f"{SELFUSE_RAW}/{relative_path(target.srs_output)}",
        "mrsAliases": [relative_path(path) for path in target.mrs_aliases],
        "sources": [source.name for source in target.sources],
        "excludes": [source.name for source in target.excludes],
        "subtractSources": [source.name for source in target.subtract_sources],
        "counts": counts,
    }


def write_manifest(domain_counts: dict[str, dict[str, int]], ip_counts: dict[str, int]) -> None:
    """Purpose: persist source URLs, branch origins, outputs, and counts.

    Args:
        domain_counts: Per-target domain counts.
        ip_counts: Per-source and merged IP/CIDR counts.

    Returns:
        None.
    """

    targets = {
        target.name: format_target(target, domain_counts[target.name])
        for target in DOMAIN_TARGETS
    }
    data = {
        "outputs": targets,
        "legacyDomainMrs": relative_path(LEGACY_DOMAIN_MRS),
        "ipOutput": {
            "description": "IP/CIDR ad-related blocklist.",
            "mrs": relative_path(IP_MRS),
            "sources": [source.name for source in IP_SOURCES],
            "counts": ip_counts,
        },
        "sourceCatalog": [format_source(source) for source in ALL_SOURCES],
        "sourceNotes": {
            "wuming155": "Upstream README states no redistribution; verify permission before public publishing.",
            "global": "global.mrs subtracts lite source domains to avoid China/PCDN overlap.",
        },
        "domainCounts": domain_counts["full"],
        "ipCounts": ip_counts,
    }
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(data, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    """Purpose: update full, lite, global MRS/SRS outputs and IP MRS output.

    Args:
        None.

    Returns:
        Process exit code.
    """

    if len(sys.argv) != 3:
        raise SystemExit("Usage: update_merged_ad_rules.py <mihomo-binary> <sing-box-binary>")

    cache: dict[str, set[str]] = {}
    domain_counts = {
        target.name: build_domain_target(sys.argv[1], sys.argv[2], target, cache)
        for target in DOMAIN_TARGETS
    }
    ip_counts = build_ip_rules(sys.argv[1], cache)
    write_manifest(domain_counts, ip_counts)
    print(
        " ".join(
            f"{name}={counts['merged']}"
            for name, counts in domain_counts.items()
        )
        + f" ipcidr={ip_counts['merged']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
