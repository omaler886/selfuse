#!/usr/bin/env python3
"""proxy-lite 活性刷新：全量 proxy 上游 -> 合并去重 -> UDP DNS 逐域判活 -> parked 出售页过滤
   -> 写 custom/proxy-lite.domain.txt（随后由 build_all_rules.py --only proxy-lite 编译）。
   必须在海外网络环境运行（GitHub Actions runner / 海外 VPS）。国内 UDP 53 会被 GFW 污染，结果不可信。
"""
from __future__ import annotations

import json, os, random, socket, struct, sys, time, threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_all_rules import MANIFEST, parse, fetch

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "custom" / "proxy-lite.domain.txt"
SERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
PARK_CIDRS = [(0xC73BF300, 24), (0x5BC3F000, 21), (0x67E0D400, 22)]  # Bodis / Sedo+ParkingCrew / Above.com
MIN_ALIVE = 18000  # 门禁：活域骤降说明扫描环境异常，拒绝产出

local = threading.local()


def get_sock():
    if not hasattr(local, "s"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(4)
        local.s = s
    return local.s


def build_q(name: str, txid: int) -> bytes:
    q = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for part in name.rstrip(".").split("."):
        q += bytes([len(part)]) + part.encode("idna" if any(ord(c) > 127 for c in part) else "ascii")
    return q + b"\x00" + struct.pack(">HH", 1, 1)


def skip_name(buf: bytes, off: int) -> int:
    while True:
        l = buf[off]
        if l == 0:
            return off + 1
        if l & 0xC0 == 0xC0:
            return off + 2
        off += l + 1


def parse_name(buf: bytes, off: int):
    labels, jumped, end = [], False, off
    for _ in range(20):
        l = buf[off]
        if l == 0:
            if not jumped:
                end = off + 1
            break
        if l & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", buf[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            off, jumped = ptr, True
            continue
        labels.append(buf[off + 1:off + 1 + l].decode("ascii", "replace"))
        off += l + 1
    return ".".join(labels), end


def parse_answers(buf: bytes, ancount: int):
    """Answer 区条目 [(rtype, rdata_abs_offset, rdlen, rdata)]。"""
    off = skip_name(buf, 12) + 4
    ents = []
    for _ in range(ancount):
        _, noff = parse_name(buf, off)
        rtype = struct.unpack(">H", buf[noff:noff + 2])[0]
        rdlen = struct.unpack(">H", buf[noff + 8:noff + 10])[0]
        ents.append((rtype, noff + 10, rdlen, buf[noff + 10:noff + 10 + rdlen]))
        off = noff + 10 + rdlen
    return ents


def first_cname_target(buf: bytes, ancount: int):
    off = skip_name(buf, 12) + 4
    for _ in range(ancount):
        _, noff = parse_name(buf, off)
        rtype = struct.unpack(">H", buf[noff:noff + 2])[0]
        rdlen = struct.unpack(">H", buf[noff + 8:noff + 10])[0]
        if rtype == 5:
            return parse_name(buf, noff + 10)[0]
        off = noff + 10 + rdlen
    return None


def udp_query(name: str, server: str):
    txid = random.randint(0, 65535)
    s = get_sock()
    for _ in range(2):
        try:
            s.sendto(build_q(name, txid), (server, 53))
            buf, _ = s.recvfrom(4096)
            if struct.unpack(">H", buf[0:2])[0] != txid:
                continue
            rc = buf[3] & 0x0F
            if rc == 3:
                return "dead", None
            if rc != 0:
                return "error", None
            ancount = struct.unpack(">H", buf[6:8])[0]
            ents = parse_answers(buf, ancount)
            if any(t == 1 for t, *_ in ents):
                return "alive", None
            return "noanswer", first_cname_target(buf, ancount)
        except Exception:
            continue
    return "error", None


def ip_int(ip: str):
    try:
        p = ip.split(".")
        return (int(p[0]) << 24) | (int(p[1]) << 16) | (int(p[2]) << 8) | int(p[3])
    except Exception:
        return None


def is_park(ip: str) -> bool:
    v = ip_int(ip)
    for base, mask in PARK_CIDRS:
        if v is not None and (v >> (32 - mask)) == (base >> (32 - mask)):
            return True
    return False


def get_ips(d: str):
    txid = random.randint(0, 65535)
    s = get_sock()
    for _ in range(2):
        try:
            s.sendto(build_q(d, txid), (random.choice(SERVERS), 53))
            buf, _ = s.recvfrom(4096)
            if struct.unpack(">H", buf[0:2])[0] != txid:
                continue
            if buf[3] & 0x0F != 0:
                return []
            ancount = struct.unpack(">H", buf[6:8])[0]
            return [".".join(str(b) for b in r) for t, _, _, r in parse_answers(buf, ancount)
                    if t == 1 and len(r) == 4]
        except Exception:
            continue
    return []


def tcp_alive(d: str, ips: list[str]) -> bool:
    """L3 服务存活：对解析出的 IP 做 443/80 TCP 握手，握手成功才算有服务在跑。"""
    for ip in ips[:3]:
        for port in (443, 80):
            try:
                s = socket.create_connection((ip, port), timeout=3)
                s.close()
                return True
            except Exception:
                continue
    return False


def judge(d: str) -> str:
    s0 = random.randrange(3)
    st, cn = udp_query(d, SERVERS[s0])
    if st == "error":
        st, cn = udp_query(d, SERVERS[(s0 + 1) % 3])
    if st == "alive":
        return "alive"
    if st == "dead":
        return "dead"
    if st == "noanswer" and cn:
        st2, _ = udp_query(cn, SERVERS[(s0 + 2) % 3])
        return "alive" if st2 == "alive" else "dead"
    if st == "noanswer":
        return "dead"
    if st == "error":
        st, cn = udp_query(d, SERVERS[(s0 + 2) % 3])
        if st == "alive":
            return "alive"
        if st == "dead":
            return "dead"
        if st == "noanswer":
            if cn:
                st2, _ = udp_query(cn, SERVERS[s0])
                return "alive" if st2 == "alive" else "dead"
            return "dead"
        return "unknown"  # 扫描环境异常：保守保留
    return "unknown"


def load_upstream_domains() -> list[str]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    entry = None

    def find(o):
        nonlocal entry
        if isinstance(o, dict):
            if o.get("name") == "proxy":
                entry = o
                return True
            for v in o.values():
                if find(v):
                    return True
        elif isinstance(o, list):
            for v in o:
                if find(v):
                    return True
        return False

    assert find(manifest), "manifest 中找不到 proxy 集"
    entries = []
    for src in entry["sources"]:
        entries += parse(fetch(src["url"]), src["kind"])
    doms = sorted({v for t, v in entries if t in ("suffix", "exact")})
    print(f"upstream merge: {len(doms)} domains")
    return doms


def main():
    doms = load_upstream_domains()
    t0 = time.time()
    res = {}
    with ThreadPoolExecutor(max_workers=150) as ex:
        futs = {ex.submit(judge, d): d for d in doms}
        for i, (f, d) in enumerate(futs.items()):
            res[d] = f.result()
            if (i + 1) % 5000 == 0:
                print(f"  scanned {i + 1}/{len(doms)} {time.time() - t0:.0f}s", flush=True)
    stat = {}
    for v in res.values():
        stat[v] = stat.get(v, 0) + 1
    print("scan result:", stat, f"{time.time() - t0:.0f}s")

    alive = [d for d, v in res.items() if v == "alive"]
    parked, tcp_dead = {}, []

    def work(d):
        ips = get_ips(d)
        if any(is_park(ip) for ip in ips):
            parked[d] = [ip for ip in ips if is_park(ip)]
            return
        if ips and not tcp_alive(d, ips):
            tcp_dead.append(d)  # DNS 活但 443/80 都不握手：服务已死

    with ThreadPoolExecutor(max_workers=200) as ex:
        list(ex.map(work, alive))
    final = sorted(d for d in alive if d not in parked and d not in tcp_dead)
    print(f"parked removed: {len(parked)}, tcp-dead removed: {len(tcp_dead)}, final: {len(final)}")

    if len(final) < MIN_ALIVE:
        print(f"gate failed: alive {len(final)} < {MIN_ALIVE}, refusing to write")
        sys.exit(1)

    header = (
        "# proxy-lite —— 全量 proxy 上游逐域 DNS+TCP 活性筛选（GitHub Actions runner, 海外直连）\n"
        "# L1 剔 NXDOMAIN；L2 剔 parked 出售页（Bodis/Sedo/Above 特征段）；L3 剔 443/80 均不握手的死服务；unknown 保守保留\n"
        f"# 最近刷新: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}  "
        f"上游 {len(doms)} -> alive {len(alive)} - parked {len(parked)} - tcp-dead {len(tcp_dead)} = {len(final)}\n"
    )
    OUT.write_text(header + "\n".join(final) + "\n", encoding="utf-8", newline="\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(
                f"## proxy-lite refresh\n\nupstream {len(doms)} -> alive {len(alive)} -> parked -{len(parked)} -> tcp-dead -{len(tcp_dead)} -> **final {len(final)}**\n\n"
                f"stat: `{stat}`\n")
    print("written", OUT)


if __name__ == "__main__":
    main()
