#!/usr/bin/env python3
"""proxy-lite 活性刷新：全量 proxy 上游 -> 合并去重 -> UDP DNS 逐域判活 -> parked 出售页过滤
   -> 写 custom/proxy-lite.domain.txt（随后由 build_all_rules.py --only proxy-lite 编译）。
   必须在海外网络环境运行（GitHub Actions runner / 海外 VPS）。国内 UDP 53 会被 GFW 污染，结果不可信。
"""
from __future__ import annotations

import json, os, random, re, socket, ssl, struct, sys, time, threading
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


# ── L2b 停放商 NS 指纹 ────────────────────────────────────────────
# 比页面内容更早、更稳的信号：域名一进停放商，NS 立刻切过去，页面可能还没挂上。
# 数据源：MISP warninglists / parking-domain-ns（见 data/parking-ns.txt 头部注释）
PARKING_NS: list[str] = []   # 由 load_parking_ns() 填充


def load_parking_ns(path=None) -> int:
    global PARKING_NS
    p = Path(path) if path else (ROOT / "data" / "parking-ns.txt")
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
        # 按长度降序：最长后缀优先命中（如 ns1.undeveloped.com 优先于裸 undeveloped.com）
        PARKING_NS = sorted(
            (l.strip().lower().rstrip(".") for l in lines
             if l.strip() and not l.lstrip().startswith("#")),
            key=len, reverse=True)
    except Exception as e:
        print(f"warn: 停放商 NS 库未加载（{p}）: {e}", flush=True)
        PARKING_NS = []
    print(f"parking-ns 库: {len(PARKING_NS)} 条", flush=True)
    return len(PARKING_NS)


def match_parking_ns(ns_list) -> str | None:
    """NS 后缀匹配，返回命中的后缀；未命中返回 None。"""
    for ns in ns_list:
        for suf in PARKING_NS:
            if ns == suf or ns.endswith("." + suf):
                return suf
    return None


def query_ns(d: str) -> list[str]:
    """查 NS 记录（qtype=2），返回小写去尾点列表。NS rdata 可能带压缩指针，用 parse_name 解。"""
    txid = random.randint(0, 65535)
    s = get_sock()
    for _ in range(2):
        try:
            s.sendto(build_q(d, txid, 2), (random.choice(SERVERS), 53))
            buf, _ = s.recvfrom(4096)
            if struct.unpack(">H", buf[0:2])[0] != txid:
                continue
            if buf[3] & 0x0F != 0:
                return []
            ancount = struct.unpack(">H", buf[6:8])[0]
            out = []
            for t, off, _rdlen, _r in parse_answers(buf, ancount):
                if t == 2:  # NS
                    name, _ = parse_name(buf, off)
                    if name:
                        out.append(name.lower().rstrip("."))
            return out
        except Exception:
            continue
    return []


# L3 探测端口（补 CF 备用 HTTPS 端口 2053/2083/2087/2096 + 8080）
PROBE_PORTS = (443, 80, 8443, 8080, 2053, 2083, 2087, 2096)

# L4 响应读取上限：2048 -> 8192。停放页的跳转脚本/模板常落在 2KB 之后。
MAX_BODY = 8192


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


# ── L4 内容层标记表 ──────────────────────────────────────────────
# 三张表分工（依据 Cloudflare 官方 1xxx 错误码文档语义）：
#   SALE_MARKS   挂售/停放页 + CF「配置错误」类   -> 命中即剔
#   CF_KEEP_MARKS CF「探测方被挡」类              -> 站点活着，命中即强制保留
#   CF_RECHECK    CF「可能临时」类                -> 保留，仅记入复检名单
SALE_MARKS = [
    # CF 配置错误类（放表头：同页多标记时优先记录结构化错误码）
    "error 1000", "error 1004", "error 1014", "error 1018", "error 1023",
    # 挂售 / 停放页
    "buy this domain", "domain for sale", "this domain is for sale",
    "domain may be for sale", "is for sale at", " domain sale",
    "bodis.com", "sedoparking", "hugedomains", "afternic", "dan.com/",
    "parklogic", "above.com", "namedrive", "domaincontrol.com",
    "origin is unreachable", "dns points to prohibited",
]

# CF「探测方被挡」：站点活着，只是拒绝了我们的出口 IP/ASN/地区。
# 1005 ASN banned / 1006-1008,1106 IP banned / 1009 country banned /
# 1010 browser signature / 1011 hotlink / 1012 access denied /
# 1015 rate limited / 1020 access denied
CF_KEEP_MARKS = [
    "error 1005", "error 1006", "error 1007", "error 1008", "error 1106",
    "error 1009", "error 1010", "error 1011", "error 1012",
    "error 1015", "error 1020",
]

# CF「可能临时」：源站解析失败 / 隧道故障 / 限流 —— 保留，仅记复检名单
CF_RECHECK_MARKS = [
    "error 1013", "error 1016", "error 1019", "error 1025",
    "error 1033", "error 1034", "error 530",
]

# 标记表必须是 bytes —— body 是 bytes，`str in bytes` 会抛
# TypeError: a bytes-like object is required, not 'str'。
# 该异常曾被 http_probe 的 except 静默吞掉，导致所有站点落到 noresp、sale 恒为 0。
SALE_MARKS_B = tuple(m.encode() for m in SALE_MARKS)
CF_KEEP_MARKS_B = tuple(m.encode() for m in CF_KEEP_MARKS)
CF_RECHECK_MARKS_B = tuple(m.encode() for m in CF_RECHECK_MARKS)

# 停放商 host —— 用于 3xx Location 指向判定（HugeDomains 这类停放页 body 为空，
# 标记只在 Location 头里）
PARKING_HOSTS = (
    "bodis.com", "sedoparking.com", "sedo.com", "hugedomains.com", "afternic.com",
    "dan.com", "parklogic.com", "above.com", "namedrive.com", "domaincontrol.com",
    "parkingcrew.net", "undeveloped.com", "sav.com", "squadhelp.com",
    "brandbucket.com", "domainmarket.com", "perfectdomain.com", "ztomy.com",
)


def _first_hit(body: bytes, table: tuple) -> str | None:
    if not body:
        return None
    b = body.lower()
    for m in table:
        if m in b:
            return m.decode()
    return None


def cf_keep_hit(body: bytes) -> str | None:
    """命中 CF「探测方被挡」标记 -> 站点活着，强制保留。"""
    return _first_hit(body, CF_KEEP_MARKS_B)


def cf_recheck_hit(body: bytes) -> str | None:
    """命中 CF「可能临时」标记 -> 保留，仅记入复检名单。"""
    return _first_hit(body, CF_RECHECK_MARKS_B)


def redirect_to_parking(data: bytes) -> str | None:
    """3xx 且 Location 指向已知停放商 -> 返回停放商标识。
    覆盖 HugeDomains 这类「302 + 空 body，标记只在 Location 头」的停放页。"""
    head, _, _ = data.partition(b"\r\n\r\n")
    # 注意 HTTP/2 状态行是 `HTTP/2 302`（无小版本号），不能写成 HTTP/\d\.\d
    if not re.match(rb"HTTP/[\d.]+\s+3\d\d", head):
        return None
    m = re.search(rb"\r\nlocation:\s*(\S+)", b"\r\n" + head, re.I)
    if not m:
        return None
    loc = m.group(1).decode("latin1", "replace").lower()
    for h in PARKING_HOSTS:
        if h in loc:
            return h
    return None


def sale_mark(body: bytes) -> str | None:
    """返回命中的挂售标记（供 sale-pages.txt 落盘审计），未命中返回 None。"""
    return _first_hit(body, SALE_MARKS_B)


def is_sale_page(body: bytes) -> bool:
    return sale_mark(body) is not None


# http_probe 结果分布 + 失败原因计数。修复前 sale 恒为 0 且无任何可见信号，
# 靠这个分布才能确认 L4 真的在跑（noresp 里全是 443/80 的异常类型即为异常信号）。
PROBE_STAT = Counter()


def _verdict(data: bytes, via: str) -> tuple[str, str | None, str]:
    # 1) 挂售/停放页 + CF 配置错误类 -> 剔
    mk = sale_mark(data)
    if not mk:
        rh = redirect_to_parking(data)   # 3xx 指向停放商（body 为空的场景）
        if rh:
            mk = f"redirect:{rh}"
    if mk:
        PROBE_STAT["sale"] += 1
        return "sale", mk, via
    # 2) CF「探测方被挡」-> 站点活着，强制保留（单独计数，便于观察 DC IP 被挡规模）
    keep = cf_keep_hit(data)
    if keep:
        PROBE_STAT[f"cfkeep/{keep.replace(' ', '_')}"] += 1
        return "ok", None, via
    # 3) CF「可能临时」-> 保留，仅记复检
    rk = cf_recheck_hit(data)
    if rk:
        PROBE_STAT[f"cfrecheck/{rk.replace(' ', '_')}"] += 1
        return "ok", None, via
    PROBE_STAT["ok"] += 1
    return "ok", None, via


def http_probe(d: str, v4: list[str]) -> tuple[str, str | None, str | None]:
    """L4 内容层：HTTPS(SNI=d, 不验证书) 优先，失败退 HTTP80。
    返回 (verdict, mark, via)：verdict ∈ sale/ok/noresp；mark 为命中的挂售标记（仅 sale 非空）；
    via ∈ https/http（noresp 时为 None）—— 用于区分「443 挂但 80 活」与「双端口全挂」。"""
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
            while len(data) < MAX_BODY:
                chunk = ss.recv(2048)
                if not chunk:
                    break
                data += chunk
            return _verdict(data, "https")
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
            while len(data) < MAX_BODY:
                chunk = s.recv(2048)
                if not chunk:
                    break
                data += chunk
            return _verdict(data, "http")
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
    return "noresp", None, None


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
    load_parking_ns()
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
    parked_ns = {}  # L2b: domain -> 命中的停放商 NS 后缀
    # 只读诊断：均「保守保留」，仅导出名单供后续分析，不影响本层判定
    http_only, noresp = [], []  # 443 挂但 80 活 / 443+80 双端口全挂

    def work(d):
        addrs = get_addrs(d)
        v4 = [ip for ip, _ in addrs if "." in ip]
        if any(is_park(ip) for ip in v4):
            parked[d] = [ip for ip in v4 if is_park(ip)]
            return
        if not addrs:
            return
        # L2b: 停放商 NS 指纹 —— 比页面内容更早更稳，命中即剔
        ns = query_ns(d)
        if ns:
            hit_ns = match_parking_ns(ns)
            if hit_ns:
                parked_ns[d] = hit_ns
                return
        verdict = tcp_probe(addrs)
        if verdict == "refused":
            tcp_dead.append(d)  # 全端口 RST：服务确实没了
            return
        if verdict == "timeout":
            tcp_timeout.append(d)  # 鉴权墙/防火墙 drop：保留
            return
        verdict, mk, via = http_probe(d, v4)
        if verdict == "sale":
            sale_pages[d] = mk  # L4 内容层：挂售页 / CDN 源站死错误页
        elif verdict == "noresp":
            noresp.append(d)  # 443+80 双端口全挂（诊断，仍保留）
        elif via == "http":
            http_only.append(d)  # 443 挂但 80 活（诊断，仍保留）

    with ThreadPoolExecutor(max_workers=200) as ex:
        list(ex.map(work, alive))
    final = sorted(d for d in alive
                   if d not in parked and d not in parked_ns
                   and d not in tcp_dead and d not in sale_pages)
    print(f"parked(ip) removed: {len(parked)}, parked(ns) removed: {len(parked_ns)}, "
          f"tcp-dead removed: {len(tcp_dead)}, sale/cdn-dead removed: {len(sale_pages)}, "
          f"final: {len(final)}")
    print(f"http_probe stat: {dict(PROBE_STAT.most_common())}", flush=True)
    Path("parked-ns.txt").write_text(
        "\n".join(f"{d}\t{parked_ns[d]}" for d in sorted(parked_ns)) + "\n", encoding="utf-8")
    Path("tcp-timeout.txt").write_text("\n".join(sorted(tcp_timeout)) + "\n", encoding="utf-8")
    # 只读诊断名单（不改判定）：供分析「443 挂但 80 活」「双端口全挂」两批的构成
    Path("http-only.txt").write_text("\n".join(sorted(http_only)) + "\n", encoding="utf-8")
    Path("noresp.txt").write_text("\n".join(sorted(noresp)) + "\n", encoding="utf-8")
    print(f"diagnostic: http-only(443挂/80活)={len(http_only)}, "
          f"noresp(443+80全挂)={len(noresp)}", flush=True)
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
        "# proxy-lite —— 全量 proxy 上游逐域 DNS+TCP+HTTP 内容活性筛选（GitHub Actions, 海外直连）\n"
        "# L1 剔 NXDOMAIN；L2 剔 parked 网段；L2b 剔停放商 NS 指纹（MISP parking-domain-ns）；\n"
        "# L3 剔全端口 RST 死服务；L4 剔挂售页/CF 配置错误页（1000/1004/1014/1018/1023）；\n"
        "# CF「探测方被挡」类（1005-1012/1020）与「可能临时」类（1016/1033/530）一律保留；\n"
        "# unknown 与鉴权墙超时保守保留\n"
        f"# 最近刷新: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}  "
        f"上游 {len(doms)} -> alive {len(alive)} - parked(ip) {len(parked)} - parked(ns) {len(parked_ns)}"
        f" - tcp-dead {len(tcp_dead)} - sale {len(sale_pages)} = {len(final)}\n"
    )
    OUT.write_text(header + "\n".join(final) + "\n", encoding="utf-8", newline="\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(
                f"## proxy-lite refresh\n\nupstream {len(doms)} -> alive {len(alive)} -> parked(ip) -{len(parked)} -> parked(ns) -{len(parked_ns)} -> tcp-dead -{len(tcp_dead)} -> sale/cdn-dead -{len(sale_pages)} -> **final {len(final)}**\n\n"
                f"stat: `{stat}`\n")
    print("written", OUT)


if __name__ == "__main__":
    main()
