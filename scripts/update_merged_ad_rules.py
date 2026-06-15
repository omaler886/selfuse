from __future__ import annotations

import ipaddress
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

HTTPDNS_MRS_URL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-httpdns-cn@ads.mrs"
DOMAIN_PATTERN = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z0-9-]+$", re.IGNORECASE)


@dataclass(frozen=True)
class Source:
    """Purpose: describe one MRS input for the merged ad rules.

    Args:
        name: Stable input name used for build-cache file names.
        behavior: Mihomo rule-set behavior, either domain or ipcidr.
        path: Local MRS path when the source is generated in this repo.
        url: Remote MRS URL when the source is maintained elsewhere.

    Returns:
        Immutable input metadata for the merge pipeline.
    """

    name: str
    behavior: str
    path: Path | None = None
    url: str | None = None


DOMAIN_SOURCES = (
    Source("ads-cn", "domain", ROOT / "ads-cn.mrs"),
    Source("ads-global", "domain", ROOT / "ads-global.mrs"),
    Source("monitoring-block", "domain", ROOT / "monitoring-block.mrs"),
    Source("pcdn", "domain", ROOT / "pcdn.mrs"),
    Source("httpdns-cn@ads", "domain", url=HTTPDNS_MRS_URL),
)

IP_SOURCES = (
    Source("monitoring-block-ip", "ipcidr", ROOT / "monitoring-block-ip.mrs"),
)


def fetch_file(url: str, target: Path) -> None:
    """Purpose: download a remote MRS input.

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
    """Purpose: resolve local or remote source input into a local path.

    Args:
        source: MRS input metadata.

    Returns:
        Local path containing the source MRS bytes.
    """

    if source.path:
        if not source.path.exists():
            raise FileNotFoundError(f"source MRS not found: {source.path}")

        return source.path

    if not source.url:
        raise ValueError(f"source has neither path nor url: {source.name}")

    target = BUILD_DIR / "raw" / f"{source.name}.mrs"
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

    source_path = get_source_path(source)
    target = BUILD_DIR / "expanded" / f"{source.name}.text"
    convert_ruleset(mihomo, source.behavior, "mrs", source_path, target)
    return target


def normalize_domain(value: str) -> str | None:
    """Purpose: normalize a domain rule into bare-domain form.

    Args:
        value: Raw rule line from an expanded MRS.

    Returns:
        Lowercase bare domain, or None when the line is not a domain rule.
    """

    item = value.strip().lower()
    if not item or item.startswith(("#", "!", ";", "[")):
        return None

    item = item.removeprefix("||").removeprefix("|").removeprefix(".")
    item = item.removesuffix("^").removesuffix("/")
    item = item.removeprefix("*.").removeprefix("+.")
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

    try:
        return str(ipaddress.ip_network(item, strict=False))
    except ValueError:
        return None


def read_rules(path: Path, behavior: str) -> set[str]:
    """Purpose: read normalized rules from expanded text.

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
    lines = [title, "# Auto-generated from expanded MRS inputs.", *sorted(rules)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build(mihomo: str, sources: tuple[Source, ...], text_output: Path, mrs_output: Path) -> dict[str, int]:
    """Purpose: expand, deduplicate, write, and compile one merged rule-set.

    Args:
        mihomo: Mihomo executable path.
        sources: Inputs sharing the same behavior.
        text_output: Temporary merged text rule output.
        mrs_output: Final compiled MRS output.

    Returns:
        Per-source counts plus a merged count.
    """

    behavior = sources[0].behavior
    merged_rules: set[str] = set()
    counts: dict[str, int] = {}
    for source in sources:
        expanded = expand_source(mihomo, source)
        rules = read_rules(expanded, source.behavior)
        counts[source.name] = len(rules)
        merged_rules.update(rules)

    write_rules(text_output, f"# Merged {behavior} ad blocklist for mihomo.", merged_rules)
    convert_ruleset(mihomo, behavior, "text", text_output, mrs_output)
    counts["merged"] = len(merged_rules)
    return counts


def main() -> int:
    """Purpose: update merged ad-domain and ad-ip MRS outputs.

    Args:
        None.

    Returns:
        Process exit code.
    """

    if len(sys.argv) != 2:
        raise SystemExit("Usage: update_merged_ad_rules.py <mihomo-binary>")

    domain_counts = build(sys.argv[1], DOMAIN_SOURCES, DOMAIN_OUTPUT, DOMAIN_MRS)
    ip_counts = build(sys.argv[1], IP_SOURCES, IP_OUTPUT, IP_MRS)
    print(f"domain={domain_counts['merged']} ipcidr={ip_counts['merged']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
