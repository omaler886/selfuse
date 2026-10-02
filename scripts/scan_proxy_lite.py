#!/usr/bin/env python3
"""proxy-lite 活性刷新：全量 proxy 上游 -> 合并去重 -> UDP DNS 逐域判活 -> parked 出售页过滤
   -> 写 custom/proxy-lite.domain.txt（随后由 build_all_rules.py --only proxy-lite 编译）。
   必须在海外网络环境运行（GitHub Actions runner / 海外 VPS）。国内 UDP 53 会被 GFW 污染，结果不可信。
"""
from __future__ import annotations

import json, os, random, socket, ssl, struct, sys, time, threading
from collections import Counter
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


def build_q(name: str, txid: int, qtype: int = 1) -> bytes:
    q = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for part in name.rstrip(".").split("."):
        q += bytes([len(part)]) + part.encode("idna" if any(ord(c) > 127 for c in part) else "ascii")
    return q + b"\x00" + struct.pack(">HH", qtype, 1)


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


def get_addrs(d: str):
    """返回 [(addr, family)]：A 与 AAAA 都查，v6-only 站点也拿得到地址。"""
    txid = random.randint(0, 65535)
    s = get_sock()
    out = []
    for qtype, fam in ((1, socket.AF_INET), (28, socket.AF_INET6)):
        for _ in range(2):
            try:
                s.sendto(build_q(d, txid, qtype), (random.choice(SERVERS), 53))
                buf, _ = s.recvfrom(4096)
                if struct.unpack(">H", buf[0:2])[0] != txid:
                    continue
                if buf[3] & 0x0F != 0:
                    break
                ancount = struct.unpack(">H", buf[6:8])[0]
                for t, _, _, r in parse_answers(buf, ancount):
                    if t == qtype and len(r) in (4, 16):
                        out.append((socket.inet_ntop(fam, r), fam))
                break
            except Exception:
                continue
    return out


PROBE_PORTS = (443, 80, 8443)


def tcp_probe(addrs) -> str:
    """L3 服务存活，三种结果：
    alive   —— 任一地址任一端口握手成功（服务在跑；HTTP 鉴权是握手后的事，不影响探测）
    refused —— 全部收到 RST（端口明确关闭，服务真死了）
    timeout —— 有超时且无成功（防火墙对数据中心 IP drop SYN：疑似鉴权墙挡探测，保守保留）
    """
    refused = True
    for host, fam in addrs[:4]:
        for port in PROBE_PORTS:
            s = None
            try:
                s = socket.socket(fam, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((host, port))
                return "alive"
            except ConnectionRefusedError:
                continue
            except OSError:
                refused = False  # 超时/不可达：不能断定死
                continue
            finally:
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
    return "refused" if refused else "timeout"


# L4：挂售页/CDN 源站死的页面特征（命中即剔）
SALE_MARKS = [
    "buy this domain", "domain for sale", "this domain is for sale",
    "domain may be for sale", "is for sale at", " domain sale",
    "bodis.com", "sedoparking", "hugedomains", "afternic", "dan.com/",
    "parklogic", "above.com", "namedrive", "domaincontrol.com",
    "error 1000", "error 1016", "error 1033", "error 530",
    "origin is unreachable", "dns points to prohibited",
]


# 标记表必须是 bytes —— body 是 bytes，`str in bytes` 会抛
# TypeError: a bytes-like object is required, not 'str'。
# 该异常曾被 http_probe 的 except 静默吞掉，导致所有站点落到 noresp、sale 恒为 0。
SALE_MARKS_B = tuple(m.encode() for m in SALE_MARKS)


def sale_mark(body: bytes) -> str | None:
    """返回命中的标记（供 sale-pages.txt 落盘审计），未命中返回 None。"""
    if not body:
        return None
    b = body.lower()
    for m in SALE_MARKS_B:
        if m in b:
            return m.decode()
    return None


def is_sale_page(body: bytes) -> bool:
    return sale_mark(body) is not None


# http_probe 结果分布 + 失败原因计数。修复前 sale 恒为 0 且无任何可见信号，
# 靠这个分布才能确认 L4 真的在跑（noresp 里全是 443/80 的异常类型即为异常信号）。
PROBE_STAT = Counter()


def _verdict(data: bytes) -> tuple[str, str | None]:
    mk = sale_mark(data)
    if mk:
        PROBE_STAT["sale"] += 1
        return "sale", mk
    PROBE_STAT["ok"] += 1
    return "ok", None


def http_probe(d: str, v4: list[str]) -> tuple[str, str | None]:
    """L4 内容层：HTTPS(SNI=d, 不验证书) 优先，失败退 HTTP80。
    返回 (verdict, mark)：verdict ∈ sale/ok/noresp，mark 为命中的挂售标记（仅 sale 非空）。"""
    ua = f"GET / HTTP/1.1\r\nHost: {d}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for ip in v4[:2]:
        s = None
        try:
            s = socket.create_connection((ip, 443), timeout=5)
            ss = ctx.wrap_socket(s, server_hostname=d)
            ss.sendall(ua)
            data = b""
            while len(data) < 2048:
                chunk = ss.recv(1024)
                if not chunk:
                    break
                data += chunk
            return _verdict(data)
        except Exception as e:
            PROBE_STAT[f"err443/{type(e).__name__}"] += 1
            continue
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
    for ip in v4[:2]:
        s = None
        try:
            s = socket.create_connection((ip, 80), timeout=5)
            s.sendall(ua)
            data = b""
            while len(data) < 2048:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
            return _verdict(data)
        except Exception as e:
            PROBE_STAT[f"err80/{type(e).__name__}"] += 1
            continue
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
    PROBE_STAT["noresp"] += 1
    return "noresp", None


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
    parked, tcp_dead, tcp_timeout, sale_pages = {}, [], [], {}  # sale_pages: domain -> 命中标记

    def work(d):
        addrs = get_addrs(d)
        v4 = [ip for ip, _ in addrs if "." in ip]
        if any(is_park(ip) for ip in v4):
            parked[d] = [ip for ip in v4 if is_park(ip)]
            return
        if not addrs:
            return
        verdict = tcp_probe(addrs)
        if verdict == "refused":
            tcp_dead.append(d)  # 全端口 RST：服务确实没了
            return
        if verdict == "timeout":
            tcp_timeout.append(d)  # 鉴权墙/防火墙 drop：保留
            return
        verdict, mk = http_probe(d, v4)
        if verdict == "sale":
            sale_pages[d] = mk  # L4 内容层：挂售页 / CDN 源站死错误页

    with ThreadPoolExecutor(max_workers=200) as ex:
        list(ex.map(work, alive))
    final = sorted(d for d in alive if d not in parked and d not in tcp_dead and d not in sale_pages)
    print(f"parked removed: {len(parked)}, tcp-dead removed: {len(tcp_dead)}, "
          f"sale/cdn-dead removed: {len(sale_pages)}, final: {len(final)}")
    print(f"http_probe stat: {dict(PROBE_STAT.most_common())}", flush=True)
    Path("tcp-timeout.txt").write_text("\n".join(sorted(tcp_timeout)) + "\n", encoding="utf-8")
    # 带命中标记落盘：区分「挂售/停放」（该剔）与「CF 源站错误页」（可能误杀），便于抽查审计
    Path("sale-pages.txt").write_text(
        "\n".join(f"{d}\t{sale_pages[d]}" for d in sorted(sale_pages)) + "\n", encoding="utf-8")
    mark_stat = {}
    for mk in sale_pages.values():
        mark_stat[mk] = mark_stat.get(mk, 0) + 1
    print(f"sale mark stat: {dict(sorted(mark_stat.items(), key=lambda kv: -kv[1]))}", flush=True)

    if len(final) < MIN_ALIVE:
        print(f"gate failed: alive {len(final)} < {MIN_ALIVE}, refusing to write")
        sys.exit(1)

    header = (
        "# proxy-lite —— 全量 proxy 上游逐域 DNS+TCP+HTTP 内容四层活性筛选（GitHub Actions, 海外直连）\n"
        "# L1 剔 NXDOMAIN；L2 剔 parked 特征段；L3 剔全端口 RST 死服务；L4 剔挂售页/CDN 源站死错误页；unknown 与鉴权墙超时保守保留\n"
        f"# 最近刷新: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}  "
        f"上游 {len(doms)} -> alive {len(alive)} - parked {len(parked)} - tcp-dead {len(tcp_dead)} - sale {len(sale_pages)} = {len(final)}\n"
    )
    OUT.write_text(header + "\n".join(final) + "\n", encoding="utf-8", newline="\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(
                f"## proxy-lite refresh\n\nupstream {len(doms)} -> alive {len(alive)} -> parked -{len(parked)} -> tcp-dead -{len(tcp_dead)} -> sale/cdn-dead -{len(sale_pages)} -> **final {len(final)}**\n\n"
                f"stat: `{stat}`\n")
    print("written", OUT)


if __name__ == "__main__":
    main()
