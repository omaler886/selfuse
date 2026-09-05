#!/bin/bash
# Sync upstream .srs snapshots into sing-box/rule-set/upstream/ (+ compile customs).
# Runs in GitHub Actions daily; safe to run manually.
set -euo pipefail
cd "$(dirname "$0")/../.."

UPSTREAM_DIR="sing-box/rule-set/upstream"
RULESET_DIR="sing-box/rule-set"
mkdir -p "$UPSTREAM_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

DUSTIN="https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset"
META="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing"

declare -A MAP=(
  [ad-domain]="$DUSTIN/ads.srs"
  [ad-ip]="$META/geo/geoip/ad.srs"
  [private]="$DUSTIN/private.srs"
  [private-ip]="$DUSTIN/privateip.srs"
  [cn]="$DUSTIN/cn.srs"
  [cn_ip]="$DUSTIN/cnip.srs"
  [cn-game]="$DUSTIN/games-cn.srs"
  [talkatone]="$META/geo/geosite/talkatone.srs"
  [spotify]="$DUSTIN/spotify.srs"
  [ai]="$DUSTIN/ai.srs"
  [onedrive]="$META/geo/geosite/onedrive.srs"
  [telegramip]="$DUSTIN/telegramip.srs"
  [telegram]="$META/geo/geosite/telegram.srs"
  [google_cn]="$DUSTIN/google-cn.srs"
  [google]="$META/geo/geosite/google.srs"
  [epicgames]="$META/geo/geosite/epicgames.srs"
  [trackerslist]="$META/geo/geosite/tracker.srs"
  [ntp]="$META/geo/geosite/category-ntp.srs"
  [dlsite]="$META/geo/geosite/dlsite.srs"
  [ehentai]="$META/geo/geosite/ehentai.srs"
  [netflix]="$DUSTIN/netflix.srs"
  [discord]="$META/geo/geosite/discord.srs"
  [google_ip]="$META/geo/geoip/google.srs"
  [netflix-ip]="$DUSTIN/netflixip.srs"
  [applications]="$DUSTIN/applications.srs"
  [microsoft-cn]="$DUSTIN/microsoft-cn.srs"
  [apple-cn]="$DUSTIN/apple-cn.srs"
  [geolocation-!cn]="$META/geo/geosite/geolocation-!cn.srs"
  [DouYin]="$META/geo/geosite/douyin.srs"
  [xiaohongshu]="$META/geo/geosite/xiaohongshu.srs"
  [zhihu]="$META/geo/geosite/zhihu.srs"
  [sina]="$META/geo/geosite/sina.srs"
)

CHANGED=0
for tag in "${!MAP[@]}"; do
  url="${MAP[$tag]}"
  dst="$UPSTREAM_DIR/$tag.srs"
  if curl -sL --retry 3 --max-time 120 -o "$TMP/$tag.srs" "$url"; then
    if [ ! -f "$dst" ] || ! cmp -s "$TMP/$tag.srs" "$dst"; then
      cp "$TMP/$tag.srs" "$dst"
      echo "updated: $tag"
      CHANGED=1
    fi
  else
    echo "FAILED download: $tag $url" >&2
  fi
done

# Customs: re-compile from liuyisi-afk rule-set-src (needs sing-box binary for `rule-set compile`)
LIUYISI="https://raw.githubusercontent.com/liuyisi-afk/mihomo_self_rule/main/sing-box/rule-set-src"
if [ -x ./sing-box-bin/sing-box ]; then
  SB=./sing-box-bin/sing-box
elif command -v sing-box >/dev/null 2>&1; then
  SB=sing-box
else
  echo "no sing-box binary, downloading official build for compile..."
  curl -sL --retry 3 --max-time 180 -o "$TMP/sb.tar.gz" \
    "https://github.com/SagerNet/sing-box/releases/download/v1.14.0/sing-box-1.14.0-linux-amd64.tar.gz"
  tar xzf "$TMP/sb.tar.gz" -C "$TMP"
  SB="$(find "$TMP" -name sing-box -type f | head -1)"
  chmod +x "$SB"
fi
for name in flow sakura_domian; do
  curl -sL --retry 3 --max-time 60 -o "$TMP/$name.json" "$LIUYISI/$name.json" \
    && "$SB" rule-set compile --output "$TMP/$name.srs" "$TMP/$name.json" \
    && { if [ ! -f "$RULESET_DIR/$name.srs" ] || ! cmp -s "$TMP/$name.srs" "$RULESET_DIR/$name.srs"; then
           cp "$TMP/$name.srs" "$RULESET_DIR/$name.srs"
           echo "updated: $name"
           CHANGED=1
         fi; } \
    || echo "FAILED custom: $name" >&2
done

echo "CHANGED=$CHANGED"
