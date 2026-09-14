#!/usr/bin/env python3
"""
Генератор пресетов nfqws2 для keen-pbr-sb.

Единый источник правды: все профили собираются отсюда, поэтому инварианты
(IPV6_ENABLED, соответствие filter-* и *_PORTS, key=/inseq= у каждого circular,
required-blobs.txt) не могут разъехаться между файлами.

Запуск:  python3 build_scripts/build-nfqws-strategies.py <каталог-назначения>
"""
import hashlib
import json
import os
import re
import sys

# ─────────────────────────────────────────────────────────────────────────────
# Общие константы
# ─────────────────────────────────────────────────────────────────────────────

TCP_PORTS = "80,443,1984,2053,2083,2087,2096,5222,8443"
UDP_PORTS = "443,590:600,1400,3478:3481,5349,19294:19344,49152:65535"

FILTER_TCP = "443,80,1984,2053,2083,2087,2096,5222,8443"   # == TCP_PORTS
FILTER_UDP_MAIN = "590-600,1400,3478-3481,5349,19294-19344,49152-65535"

BLOBS = "/opt/etc/nfqws2/blobs"
LISTS = "/opt/etc/nfqws2/lists"
LUA = "/opt/etc/nfqws2/lua"
ROTATOR_TELEMETRY_LUA = (
    "/opt/var/lib/keen-pbr/nfqws-rotator-telemetry-v1.lua"
)
ROTATOR_TELEMETRY_WRITABLE = "/var/run/keen-pbr-nfqws"
# nfqws2-keenetic 1.2.6 queues only the first 15 reply packets.  Keep the
# stock success proof comfortably inside that existing visibility window:
# 8 KiB is application data, while the former 18/24 KiB thresholds were
# marginal or unreachable and therefore could never make a rotated slot
# durable on the live router.
ROTATOR_TCP_SUCCESS_INSEQ = 8192
# nfqws range cutoffs match the packet start position.  Keep enough of the
# incoming stream visible for standard_success_detector to observe a packet
# beyond inseq (one maximum TCP payload past the threshold).
ROTATOR_TCP_REPLY_RANGE_SEQ = ROTATOR_TCP_SUCCESS_INSEQ + 1460
# udp_in=1 proves success on the second incoming datagram.
ROTATOR_UDP_REPLY_RANGE_PACKETS = 2

# alias -> файл в /opt/etc/nfqws2/blobs
BLOB_FILES = {
    "tls_google":    "tls_clienthello_www_google_com.bin",
    "tls_onetrust":  "tls_clienthello_www_onetrust_com.bin",
    "tls_activated": "tls_clienthello_activated.bin",
    "tls_gosuslugi": "tls_clienthello_gosuslugi_ru.bin",
    "tls_vk":        "tls_clienthello_vk_com.bin",
    "tls_4pda":      "tls_clienthello_4pda_to.bin",
    "tls_14":        "tls_clienthello_14.bin",
    "tls_max":       "tls_clienthello_max_ru.bin",
    "tls_t2":        "tls_clienthello_t2.bin",
    "quic_google":   "quic_initial_www_google_com.bin",
    "quic_ozon":     "quic_initial_ozon_ru.bin",
    "quic_rutracker": "quic_initial_rutracker_org.bin",
    "quic_dbank":    "quic_initial_dbankcloud_ru.bin",
    "quic_steam":    "quic_initial_steamcommunity_com.bin",
    "quic_4":        "quic_initial_4.bin",
    "quic_5":        "quic_initial_5.bin",
    "quic_6":        "quic_initial_6.bin",
    "stun_fake":     "stun.bin",
    "syn_data":      "syn_packet.bin",
    "http_iana":     "http_iana_org.bin",
    "zero256":       "zero_256.bin",
}
# штатные блобы самого nfqws2 — не наши, поставляются пакетом nfqws2
STOCK_BLOBS = {"quic_initial", "tls_clienthello"}

# Домены пулов. Держим короткими: это горячий путь матчинга.
YT_DOMAINS = ("youtube.com,youtu.be,ytimg.com,ggpht.com,"
              "youtubei.googleapis.com,jnn-pa.googleapis.com,yt-video-upload.l.google.com")
GV_DOMAINS = "googlevideo.com,gvt1.com,gvt2.com"
DISCORD_DOMAINS = "discord.com,discord.gg,discordapp.com,discordapp.net,discord.media"

# ─────────────────────────────────────────────────────────────────────────────
# Тиры TCP (общий пул). Каждый тир — список действий без :strategy=N,
# номер проставляется при сборке.
# ─────────────────────────────────────────────────────────────────────────────

TCP_TIERS = [
    # 1-5 — исходные тиры ver9/ver10 с исправленной изоляцией fake.
    # +10000 alone is valid out-of-order TCP data and can corrupt the stream.
    # Negative offsets prevented that in a Linux model, but repeatedly broke
    # GitHub TLS on the real Keenetic WAN. Keep the working positive offset
    # with an independent invalid checksum: the peer must discard fake data.
    # This is a preset candidate, not a promise of bypass on every network.
    ["fake:blob=tls_clienthello:optional:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000:badsum",
     "multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up"],

    ["fake:blob=tls_clienthello:optional:tcp_ack=-66000:tls_mod=rnd,dupsid,sni=www.google.com:tcp_ts_up:repeats=2",
     "multisplit:pos=1,midsld"],

    ["hostfakesplit:host=ozon.ru:midhost=host-2:seqovl=sniext+3:seqovl_pattern=tls_clienthello:badsum:tcp_md5:tcp_ts_up",
     "hostfakesplit:tcp_md5:tcp_ts_up"],

    ["multidisorder:pos=1,midsld:seqovl=3:seqovl_pattern=tls_clienthello:tcp_ts_up"],

    ["fake:blob=tls_clienthello:optional:tls_mod=rnd,dupsid,sni=www.microsoft.com:tcp_seq=10000:badsum:ip_autottl=1,3-12",
     "multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up"],

    # 6-8 — наши тиры из ver10, тир 8 с ИСПРАВЛЕННЫМ max.ru
    ["multisplit:pos=2:seqovl=681:seqovl_pattern=tls_google:optional"],

    ["fake:blob=stun_fake:optional:tcp_seq=10000:badsum:repeats=6",
     "multisplit:pos=2,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up"],

    ["fake:blob=tls_max:optional:tcp_ack=-66000:tcp_ts_up:repeats=2",
     "fake:blob=tls_4pda:optional:tcp_ack=-66000:tcp_ts_up",
     "multisplit:pos=2,midsld:tcp_ts_up"],

    # 9-12 — идеи из z2k, адаптированные к API zapret2.
    # Stock zapret2 ignores nfqws1's badseq / badseq_increment arguments.
    # Explicit negative seq/ack offsets keep these fake bytes behind the
    # real stream; badsum remains an independent part of these candidates.
    # seqovl подобран под точный размер блоба: onetrust=664 Б, activated=655 Б.
    ["fake:blob=tls_onetrust:optional:repeats=8:tcp_seq=-10000:tcp_ack=-66000:badsum",
     "multisplit:pos=1:seqovl=664:seqovl_pattern=tls_onetrust:optional"],

    ["fake:blob=tls_activated:optional:repeats=8:tcp_seq=-10000:tcp_ack=-66000:badsum",
     "multisplit:pos=1:seqovl=654:seqovl_pattern=tls_activated:optional"],

    ["fake:blob=tls_vk:optional:tcp_ts=-1000:badsum",
     "fake:blob=tls_14:optional:tcp_ts=-1000:badsum",
     "fakeddisorder:pos=10,midsld:seqovl=336:seqovl_pattern=tls_gosuslugi:optional"],

    # 12 — syndata, самый рискованный: данные в SYN. Только в максимальном профиле.
    ["syndata:blob=syn_data:optional",
     "multisplit:pos=1,sld+1,endsld-2:seqovl=1"],
]

# Тиры для YouTube-TCP: упор на google-фингерпринт
YT_TCP_TIERS = [
    ["multisplit:pos=1,sniext+1:seqovl=1"],
    ["fake:blob=tls_google:optional:repeats=6:tcp_ts=-1000:badsum:ip_id=zero",
     "multisplit:pos=1:seqovl=681:seqovl_pattern=tls_google:optional"],
    ["fake:blob=tls_google:optional:tls_mod=rnd,dupsid,sni=ggpht.com:tcp_seq=-10000:tcp_ack=-66000:badsum",
     "multisplit:pos=2,sld:seqovl=620:seqovl_pattern=tls_google:optional"],
    ["fake:blob=tls_onetrust:optional:repeats=8:tcp_seq=-10000:tcp_ack=-66000:badsum",
     "multisplit:pos=1:seqovl=664:seqovl_pattern=tls_onetrust:optional"],
    ["fake:blob=tls_clienthello:optional:tls_mod=rnd,dupsid,sni=www.google.com:badsum",
     "multidisorder:pos=1,midsld"],
    ["fake:blob=tls_t2:optional:tcp_ts=-1000:badsum:tls_mod=rnd,dupsid,sni=fonts.google.com",
     "multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello"],
]

# Тиры для googlevideo: стриминг, потоки крупнее
GV_TCP_TIERS = [
    ["multisplit:pos=1,sniext+1:seqovl=1"],
    ["fake:blob=tls_google:optional:repeats=6:tcp_ts=-1000:badsum",
     "multisplit:pos=1:seqovl=681:seqovl_pattern=tls_google:optional"],
    ["fake:blob=tls_google:optional:repeats=6:tcp_ts=-1000:badsum:ip_id=zero"],
    ["pktmod:ip_autottl=-2,3-20"],
    ["fake:blob=tls_google:optional:tcp_ts=-1000:badsum:tls_mod=rnd,dupsid,sni=fonts.google.com",
     "fakedsplit:pos=1"],
]

# QUIC — общий пул
QUIC_TIERS = [
    ["fake:blob=quic_initial:repeats=11"],
    ["fake:blob=quic_initial:repeats=6:ip_ttl=8"],
    ["fake:blob=quic_google:optional:repeats=8"],
    ["fake:blob=quic_5:optional:repeats=4:out_range=-n3",
     "send:ipfrag:ipfrag_pos_udp=8:out_range=-n3",
     "drop:out_range=-n3"],
    ["udplen:increment=4",
     "fake:blob=quic_4:optional:repeats=2:out_range=-n3"],
    ["udplen:increment=8:pattern=0xFEA82025",
     "fake:blob=quic_6:optional:repeats=2:out_range=-n4"],
]

# QUIC — пул YouTube
YT_QUIC_TIERS = [
    ["fake:blob=quic_google:optional:repeats=11"],
    ["fake:blob=quic_google:optional:repeats=8"],
    ["fake:blob=quic_google:optional:repeats=6"],
    ["fake:blob=quic_5:optional:repeats=3:out_range=-n3",
     "send:ipfrag:ipfrag_pos_udp=8:out_range=-n3",
     "drop:out_range=-n3"],
    ["udplen:increment=4",
     "fake:blob=quic_4:optional:repeats=2:out_range=-n3"],
]

# UDP — общий пул (WireGuard / STUN / Discord / MTProto)
UDP_TIERS = [
    ["fake:blob=quic_initial:repeats=6"],
    ["fake:blob=quic_initial:repeats=6:ip_ttl=8"],
    ["fake:blob=quic_5:optional:repeats=6"],          # был дублем steam-блоба
    ["fake:blob=quic_steam:optional:repeats=8"],
]

# UDP — пул Discord voice/video
DISCORD_TIERS = [
    ["fake:blob=quic_initial:repeats=6"],
    ["fake:blob=quic_5:optional:repeats=4:ip_autottl=-2,3-20"],
    ["fake:blob=quic_6:optional:repeats=6"],
    ["fake:blob=zero256:optional:repeats=2"],
]

# An experimental comparison inside Max, not a separate selectable strategy.
# Keep the same six repeats for both UDP candidates to isolate the blob.
# ACTIVE_DISCORD_UDP.bin from the nfqws1 example is our existing quic_steam.
DISCORD_EXPERIMENT_UDP_TIERS = [
    ["fake:blob=quic_initial:repeats=6"],
    ["fake:blob=quic_steam:optional:repeats=6"],
]
DISCORD_EXPERIMENT_TCP_TIERS = [
    TCP_TIERS[0],
    # Adapt the idea, not nfqws1's --dpi-desync / badseq_increment options.
    # nfqws2's stock fooling uses explicit old-data sequence/ack offsets so
    # fake bytes are not queued ahead of the real stream. These candidates are not
    # evidence that TLS, voice negotiation or actual Discord media works.
    ["fake:blob=stun_fake:optional:tcp_seq=-10000:tcp_ack=-66000:repeats=6",
     "fake:blob=tls_google:optional:tcp_seq=-10000:tcp_ack=-66000:repeats=6",
     "multisplit:pos=1,midsld"],
]

# ─────────────────────────────────────────────────────────────────────────────
# Профили
# ─────────────────────────────────────────────────────────────────────────────

PROFILES = {
    "01 safe": dict(
        title="БЕЗОПАСНЫЙ",
        note=("Ровно то же поведение, что у прежних пресетов, но без их дефектов. "
              "Общие пулы TCP/QUIC/UDP и отдельная IP-ветвь MTProto, "
              "без отдельных пулов под YouTube и Discord, "
              "без рискованных техник (syndata, ipfrag, подмена оригинала). "
              "Точка отката: если после перехода что-то сломалось — вернитесь сюда."),
        tcp=5, quic=3, udp=3, custom=False, http_fake=False,
    ),
    "02 balanced": dict(
        title="ОБЫЧНЫЙ",
        note=("Рекомендуемый. Отдельные пулы под YouTube, googlevideo, YouTube-QUIC и "
              "Discord: каждая группа подбирает стратегию независимо и параллельно. "
              "Сквозной пропуск WebRTC P2P, чтобы не ломать видеозвонки в браузере."),
        tcp=8, quic=4, udp=3, custom=True, http_fake=False,
    ),
    "03 max": dict(
        title="МАКСИМАЛЬНЫЙ",
        note=("Всё из обычного плюс четыре дополнительных тира TCP, "
              "фрагментация IP и подмена оригинала в QUIC. Последний TCP-вариант "
              "пробует syndata только на первом SYN к HTTPS/443; повторные неудачи "
              "учитываются для перехода к следующему варианту в новом соединении. "
              "Для Discord — отдельные TCP-пулы и два UDP-кандидата для начала соединения. "
              "Экспериментальный: syndata может не поддерживаться по пути, а кэш "
              "имён для SYN не различает домены на общем IP. "
              "Ставьте, только если обычный не справляется."),
        tcp=12, quic=6, udp=4, custom=True, http_fake=True, discord_experiment=True,
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# Сборка
# ─────────────────────────────────────────────────────────────────────────────


def pool(tiers, count):
    """Разворачивает тиры в список --lua-desync с проставленным strategy=N."""
    out = []
    for index, tier in enumerate(tiers[:count], start=1):
        for action in tier:
            out.append(f"--lua-desync={action}:strategy={index}")
    return out


def circular(
    key,
    *,
    fails=2,
    reset=False,
    inseq=None,
    retrans=2,
    udp=False,
    maxseq=None,
    hostkey=None,
    failure_detector=None,
    tcp_window=False,
):
    """circular с обязательным key= (стабильное пространство состояний)."""
    parts = [f"fails={fails}", "time=300"]
    if udp:
        parts += ["udp_in=1", "udp_out=4"]
    else:
        parts += [f"retrans={retrans}"]
        if inseq:
            parts.append(f"inseq={inseq}")
        if maxseq:
            parts.append(f"maxseq={maxseq}")
    if reset:
        parts.append("reset=1")
    parts += [f"hostkey={hostkey}"] if hostkey else ["nld=2"]
    if failure_detector:
        parts.append(f"failure_detector={failure_detector}")
    if not udp:
        parts.append("success_detector=keen_pbr_tcp_success_detector")
    if tcp_window:
        parts.append("kpbr_tcp_window=96")
        parts.append("kpbr_tcp_reply=postnat_v1")
    parts.append(f"key={key}")
    return "--lua-desync=circular:" + ":".join(parts)


def revisioned_circular(key, matcher, actions, **options):
    """Bind a learned slot to the exact matcher, detector and action pool."""
    detector = circular(key, **options)
    material = "\0".join([*matcher, detector, *actions]).encode("utf-8")
    revision = hashlib.sha256(material).hexdigest()[:16]
    return f"{detector}:kpbr_rev={revision}"


def tcp_pool(count, payload, *, syn=False):
    """SYN is a separate packet phase of slot 12, never a ClientHello action.

    A declined SYN-with-data attempt must not repeat forever: try it only on
    the first packet. Its connection-local detector counts SYN retries so the
    ordinary fails=2 circle can leave this slot on a subsequent connection.
    MTProto is selected after classification and cannot use the SYN phase.
    """
    result = []
    for slot, tier in enumerate(TCP_TIERS[:count], 1):
        for action in tier:
            if action.startswith("syndata:"):
                if syn:
                    result += ["--payload=empty", "--out-range=-n1",
                               "--lua-desync=keen_pbr_" + action + f":strategy={slot}",
                               "--out-range=-s66996", f"--payload={payload}"]
            else:
                result.append(f"--lua-desync={action}:strategy={slot}")
    return result


def discord_experiment_blocks():
    """Narrow, independently learned pools inside the existing Max profile.

    Observe replies/retries, but act only on outbound handshake payloads.
    Do not widen NFQUEUE ports, process arbitrary UDP/media or send TCP RSTs.
    Common STUN ports and the WebRTC passthrough keep their previous behavior.
    """
    blocks = []
    for key, ports, domains in (
        ("discord_tcp_exp", "443", DISCORD_DOMAINS),
        ("discord_media_tcp_exp", "2053,2083,2087,2096,8443", "discord.media"),
    ):
        matcher = [f"--filter-tcp={ports}", "--filter-l7=tls",
                   f"--hostlist-domains={domains}",
                   f"--hostlist-exclude={LISTS}/exclude.list",
                   "--payload=all", "--out-range=-s66996",
                   f"--in-range=-s{ROTATOR_TCP_REPLY_RANGE_SEQ}"]
        actions = ["--in-range=x", "--payload=tls_client_hello"] + pool(
            DISCORD_EXPERIMENT_TCP_TIERS, 2)
        blocks.append([f"--new={key}"] + matcher + [revisioned_circular(
            key, matcher, actions, hostkey="host_ip",
            inseq=ROTATOR_TCP_SUCCESS_INSEQ, maxseq=65536,
        )] + actions)

    # Deliberately no STUN-wide 3478/5349 capture. The protocol check is also
    # required: sharing these ports is not proof that a packet is Discord.
    matcher = ["--filter-udp=50000-50099,19294-19344",
               "--filter-l7=discord,stun", "--payload=all",
               "--out-range=-n4", "--in-range=-n2"]
    actions = ["--in-range=x", "--out-range=<n2",
               "--payload=discord_ip_discovery,stun"] + pool(
                   DISCORD_EXPERIMENT_UDP_TIERS, 2)
    blocks.append(["--new=discord_udp_exp"] + matcher + [revisioned_circular(
        "discord_udp_exp", matcher, actions, hostkey="host_ip", udp=True,
    )] + actions)
    return blocks


def legacy_rotation_pools():
    """Only the ten reviewed legacy pools; other profile bytes stay owned there.

    Slot 1 is the exact former action. QUIC fallback already ships as
    QUIC_TIERS[1]. The two UDP actions already ship in ver1 (alt) and ver2-4.
    Independent explicit keys prevent a pool or profile from advancing another.
    """
    profiles = (
        ("default", "default"), ("ver1", "ver1"),
        ("ver1 (alt)", "ver1_alt"), ("ver2", "ver2"),
        ("ver3 safe", "ver3_safe"), ("ver4", "ver4"),
    )
    zero_udp = "fake:blob=0x00000000000000000000000000000000:repeats=2"
    quic_udp = "fake:blob=quic_initial:repeats=6"
    result = {}
    for profile, identity in profiles:
        # Keep the original unbounded outgoing QUIC action range. A shorter
        # circular range would let a later Initial bypass the orchestrator and
        # run both strategy actions directly. Incoming replies are observation
        # only, and never reach the fake actions below.
        quic = [
            "--filter-udp=443", "--filter-l7=quic", "--payload=all",
            "--out-range=a", "--in-range=-n2",
            circular(f"legacy_{identity}_quic", udp=True),
            "--in-range=x", "--out-range=a", "--payload=quic_initial",
        ] + pool([QUIC_TIERS[0], QUIC_TIERS[1]], 2)
        result[profile] = {"NFQWS_ARGS_QUIC": " ".join(quic)}
        if profile in ("default", "ver1"):
            continue
        tiers = (
            [[zero_udp], [quic_udp]] if profile == "ver1 (alt)"
            else [[quic_udp], [zero_udp]]
        )
        udp = [
            f"--filter-udp={FILTER_UDP_MAIN}",
            "--filter-l7=wireguard,stun,discord,mtproto",
            "--payload=all", "--out-range=-n4", "--in-range=-n2",
            circular(f"legacy_{identity}_udp", udp=True),
            "--in-range=x", "--out-range=<n2",
            "--payload=wireguard_initiation,wireguard_response,wireguard_cookie,"
            "stun,discord_ip_discovery,mtproto_initial",
        ] + pool(tiers, 2)
        result[profile]["NFQWS_ARGS_UDP"] = " ".join(udp)
    return result


def wrap(name, tokens, indent=None):
    """Многострочное значение с отступом: формат, который понимает панель."""
    pad = " " * (len(name) + 2) if indent is None else " " * indent
    lines = []
    current = ""
    for token in tokens:
        if current and len(current) + len(token) + 1 > 96:
            lines.append(current)
            current = token
        else:
            current = f"{current} {token}".strip()
    if current:
        lines.append(current)
    body = ("\n" + pad).join(lines)
    return f'{name}="{body}"'


def build(profile_name, spec):
    tcp_n, quic_n, udp_n = spec["tcp"], spec["quic"], spec["udp"]

    with_syn = profile_name == "03 max"
    base_pool = tcp_pool(tcp_n, "tls_client_hello,mtproto_initial", syn=with_syn)
    quic_pool = pool(QUIC_TIERS, quic_n)
    udp_pool = pool(UDP_TIERS, udp_n)

    # ── NFQWS_ARGS: общий TCP-пул (РКН и всё остальное) ──────────────────────
    # Observe server replies, empty RSTs and retransmitted application data.
    # The actions remain handshake-only. Keep HTTP out of this orchestrator:
    # circular consumes the rest of the execution plan, including untagged
    # HTTP actions, so --payload=all here would silently disable plain HTTP.
    # Do not lower inseq to 8 KiB: a TCP 16-20 freeze can happen after that.
    args = [f"--filter-tcp={FILTER_TCP}",
            "--filter-l7=" + ("unknown," if with_syn else "") + "http,tls,mtproto",
            "--payload=tls_client_hello,tls_server_hello,mtproto_initial,unknown,empty",
            "--in-range=-s27460", "--out-range=-s66996",
            circular("tcp_general", inseq=26000, maxseq=65536,
                     tcp_window=profile_name in ("02 balanced", "03 max"),
                     hostkey="keen_pbr_tcp_endpoint" if with_syn else None,
                     failure_detector="keen_pbr_syn_failure_detector" if with_syn else None),
            "--in-range=x", "--payload=tls_client_hello,mtproto_initial"] + base_pool
    args += ["--out-range=a", "--payload=http_req"]
    if spec["http_fake"]:
        args += ["--lua-desync=fake:blob=http_iana:optional:badsum"]
    args += ["--lua-desync=http_methodeol:badsum"]

    # ── NFQWS_ARGS_QUIC / _UDP: общие пулы ───────────────────────────────────
    quic = ["--filter-udp=443", "--filter-l7=quic", "--payload=quic_initial",
            circular("quic_general", udp=True)] + quic_pool

    udp = [f"--filter-udp={FILTER_UDP_MAIN}",
           "--filter-l7=wireguard,stun,discord,mtproto", "--out-range=<n2",
           "--payload=wireguard_initiation,wireguard_response,wireguard_cookie,"
           "stun,discord_ip_discovery,mtproto_initial",
           circular("udp_general", udp=True)] + udp_pool

    # ── NFQWS_ARGS_CUSTOM: именованные пулы, матчатся ПЕРВЫМИ ────────────────
    custom = []
    if spec["custom"]:
        excl = f"--hostlist-exclude={LISTS}/exclude.list"
        gv_n = min(5, tcp_n)
        yt_n = min(6, tcp_n)
        yq_n = min(5, quic_n + 1)
        dc_n = min(4, udp_n + 1)

        gv_matcher = [
            f"--filter-tcp={FILTER_TCP}",
            "--filter-l7=tls",
            f"--hostlist-domains={GV_DOMAINS}",
            excl,
            "--payload=all",
            f"--in-range=-s{ROTATOR_TCP_REPLY_RANGE_SEQ}",
        ]
        gv_actions = [
            "--in-range=x",
            "--payload=tls_client_hello",
        ] + pool(GV_TCP_TIERS, gv_n)
        yt_matcher = [
            f"--filter-tcp={FILTER_TCP}",
            "--filter-l7=tls",
            f"--hostlist-domains={YT_DOMAINS}",
            excl,
            "--payload=all",
            f"--in-range=-s{ROTATOR_TCP_REPLY_RANGE_SEQ}",
        ]
        yt_actions = [
            "--in-range=x",
            "--payload=tls_client_hello",
        ] + pool(YT_TCP_TIERS, yt_n)
        yt_quic_matcher = [
            "--filter-udp=443",
            "--filter-l7=quic",
            f"--hostlist-domains={YT_DOMAINS},{GV_DOMAINS}",
            excl,
            "--payload=all",
            f"--in-range=-n{ROTATOR_UDP_REPLY_RANGE_PACKETS}",
        ]
        yt_quic_actions = [
            "--in-range=x",
            "--payload=quic_initial",
        ] + pool(YT_QUIC_TIERS, yq_n)

        # ВАЖНО про --new. Init-скрипт собирает строку как
        #   BASE CUSTOM --new UDP --new QUIC+IPSET --new QUIC+EXTRA
        #   --new TCP+IPSET --new TCP+EXTRA
        # то есть перед CUSTOM разделителя НЕТ (первый блок делит профиль с BASE_ARGS,
        # а там только --lua-init и --blob, они глобальные), и --new ставится ПОСЛЕ секции.
        # Поэтому первый блок идёт без имени, а каждый следующий начинается с --new=<имя>.
        # Ставить --new внутри NFQWS_ARGS/_QUIC/_UDP/_IPSET/_BASE_ARGS нельзя:
        # validate_config() в init-скрипте на это прерывает запуск.
        blocks = [
            # googlevideo идёт раньше youtube: он специфичнее
            gv_matcher + [revisioned_circular(
                "gv_tcp",
                gv_matcher,
                gv_actions,
                # A healthy googlevideo CDN must not erase another endpoint's
                # failure. Use the stock remote-IP key (also direction-stable
                # for IPv6), not a shared googlevideo.com domain record. Release
                # only the failed TCP attempt after the stock retransmission
                # threshold; keep two failed sessions before rotating a slot.
                hostkey="host_ip",
                reset=True,
                fails=2,
                inseq=ROTATOR_TCP_SUCCESS_INSEQ,
                retrans=2,
                maxseq=65536,
            )] + gv_actions,

            ["--new=yt_tcp"] + yt_matcher + [revisioned_circular(
                "yt_tcp",
                yt_matcher,
                yt_actions,
                fails=1,
                reset=True,
                inseq=ROTATOR_TCP_SUCCESS_INSEQ,
                retrans=2,
                maxseq=65536,
            )] + yt_actions,

            ["--new=yt_quic"] + yt_quic_matcher + [revisioned_circular(
                "yt_quic",
                yt_quic_matcher,
                yt_quic_actions,
                udp=True,
            )] + yt_quic_actions,

            ["--new=discord_udp", "--filter-udp=50000-50099,3478-3481,5349,19294-19344",
             "--filter-l7=discord,stun", "--out-range=<n2",
             "--payload=discord_ip_discovery,stun",
             circular("discord_udp", udp=True)] + pool(DISCORD_TIERS, dc_n),

            # сквозной пропуск WebRTC P2P: профиль без единого --lua-desync
            ["--new=webrtc_passthrough", "--filter-udp=49152-65535", "--filter-l7=stun"],
        ]
        for block in blocks:
            if spec.get("discord_experiment") and block[0] == "--new=discord_udp":
                for experimental in discord_experiment_blocks():
                    custom += experimental
            custom += block

    # IP-selected MTProto has no hostname. Keep its existing TCP actions on a
    # separate IP-only branch before adding host exclusions to TCP/QUIC IPSET.
    # Otherwise a nonempty exclude.list would also disable unrelated MTProto.
    mtproto = [f"--filter-tcp={FILTER_TCP}", "--filter-l7=mtproto",
               f"--ipset={LISTS}/ipset.list",
               f"--ipset-exclude={LISTS}/ipset_exclude.list",
               "--ipset-ip=0.0.0.0", "--payload=all",
               "--in-range=-s27460", "--out-range=-s66996",
               circular("tcp_mtproto", inseq=26000, maxseq=65536),
               "--in-range=x", "--payload=mtproto_initial"] + tcp_pool(tcp_n, "mtproto_initial")
    if custom:
        custom += ["--new=mtproto_ip"]
    custom += mtproto

    # ── блобы, которые нужны именно этому профилю ────────────────────────────
    text = " ".join(args + quic + udp + custom)
    used = set(re.findall(r"blob=([a-z_0-9]+)", text))
    used |= set(re.findall(r"seqovl_pattern=([a-z_0-9]+)", text))
    required = sorted(BLOB_FILES[a] for a in used
                      if a in BLOB_FILES and a not in STOCK_BLOBS)

    declare = [f"--writable={ROTATOR_TELEMETRY_WRITABLE}",
               f"--lua-init=@{LUA}/zapret-lib.lua",
               f"--lua-init=@{LUA}/zapret-antidpi.lua",
               f"--lua-init=@{LUA}/zapret-auto.lua",
               f"--lua-init=@{ROTATOR_TELEMETRY_LUA}",
               f"--blob=quic_initial:@{BLOBS}/quic_initial.bin",
               f"--blob=tls_clienthello:@{BLOBS}/tls_clienthello.bin"]
    for alias in sorted(a for a in used if a in BLOB_FILES):
        declare.append(f"--blob={alias}:@{BLOBS}/{BLOB_FILES[alias]}")
    if with_syn:
        # Stock cache supplies host-list selection before TLS reveals SNI.
        # It is not authoritative on shared CDN IPs; Max documents this limit.
        declare.append("--ipcache-hostname")

    tiers_note = (f"TCP {tcp_n} · QUIC {quic_n} · UDP {udp_n} · IP-ветвь MTProto"
                  + (" · отдельные пулы: googlevideo, youtube, youtube-QUIC, discord, "
                     "сквозной WebRTC" if spec["custom"] else " · без доменных пулов"))
    if spec.get("discord_experiment"):
        tiers_note += " · эксперимент: Discord TCP 2, discord.media TCP 2, Discord UDP 2"

    head = "\n".join([
        f"# keen-pbr-sb · профиль «{spec['title']}»",
        "#",
        *[f"# {line}" for line in _wrap_text(spec["note"], 88)],
        "#",
        f"# Глубина пулов: {tiers_note}",
        "# Пулы разделены по группам трафика: у каждого свой circular со своим key=.",
        "# У TCP-пулов есть inseq= под ожидаемый объём входящего трафика; UDP его не использует.",
        "#",
        "# Сгенерировано build-nfqws-strategies.py — правьте генератор, а не этот файл.",
        "",
        "# Интерфейс провайдера. Панель подставляет реальный при применении.",
        'ISP_INTERFACE="eth3"',
        "",
        "# Полный список аргументов: https://github.com/bol-van/zapret2/blob/master/docs/manual.md",
        "",
        "# Стартовые аргументы и объявление блобов",
    ])

    body = [
        head,
        wrap("NFQWS_BASE_ARGS", declare, indent=17),
        "",
        "# Основной пул: HTTPS/HTTP, всё, что не попало в отдельные пулы ниже",
        wrap("NFQWS_ARGS", args, indent=12),
        "",
        "# QUIC общий",
        wrap("NFQWS_ARGS_QUIC", quic, indent=17),
        "",
        "# UDP общий: WireGuard, STUN, Discord, MTProto (списки к нему не применяются)",
        wrap("NFQWS_ARGS_UDP", udp, indent=16),
        "",
    ]

    if custom:
        body += [
            "# Отдельные пулы. Собираются ПЕРЕД основными, поэтому матчатся первыми.",
            "# Доменные пулы учитывают exclude.list; MTProto без имени домена",
            "# использует только IP-списки. К UDP без имени домена hostlist не применяется.",
            wrap("NFQWS_ARGS_CUSTOM", custom, indent=19),
            "",
        ]
    else:
        body += ['NFQWS_ARGS_CUSTOM=""', ""]

    body += [
        "# Режимы работы, не менять",
        f'MODE_LIST="--hostlist={LISTS}/user.list --hostlist-exclude={LISTS}/exclude.list"',
        f'MODE_ALL="--hostlist-exclude={LISTS}/exclude.list"',
        f'MODE_AUTO="$MODE_LIST --hostlist-auto={LISTS}/auto.list '
        f'--hostlist-auto-debug=/opt/var/log/nfqws2.log"',
        "",
        "# $MODE_AUTO — сам находит заблокированные домены и дописывает в auto.list",
        "# $MODE_LIST — только домены из user.list",
        "# $MODE_ALL  — весь трафик, кроме exclude.list",
        'NFQWS_EXTRA_ARGS="$MODE_AUTO"',
        "",
        "# IP-списки HTTP/TLS/QUIC также учитывают исключения по видимому имени домена.",
        f'NFQWS_ARGS_IPSET="--ipset={LISTS}/ipset.list --ipset-exclude={LISTS}/ipset_exclude.list --hostlist-exclude={LISTS}/exclude.list"',
        "",
        "# IPv6 — одинаково во всех профилях, переключение пресета его не трогает",
        # Keenetic-first alpha follows the installed legacy majority and the
        # active router: applying a preset must not silently enable IPv6.
        "IPV6_ENABLED=0",
        "",
        "# Порты для правил iptables. Обязаны совпадать с --filter-tcp/--filter-udp выше,",
        "# иначе трафик уходит в очередь, не матчится ни одним фильтром и проходит зря.",
        f"TCP_PORTS={TCP_PORTS}",
        f"UDP_PORTS={UDP_PORTS}",
        "",
        'POLICY_NAME="nfqws"',
        "POLICY_EXCLUDE=0",
        "",
        "LOG_LEVEL=0",
        'LOG_DEBUG_PATH="@/opt/var/log/nfqws2-debug.log"',
        "",
        "NFQUEUE_NUM=300",
        "USER=nobody",
        "CONFIG_VERSION=1",
        "",
    ]
    return "\n".join(body), required


def _wrap_text(text, width):
    words, lines, current = text.split(), [], ""
    for word in words:
        if current and len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


def main():
    if sys.argv[1:] == ["--legacy-pools"]:
        print(json.dumps(legacy_rotation_pools(), indent=2))
        return
    target = sys.argv[1] if len(sys.argv) > 1 else "nfqws-strategies"
    for name, spec in PROFILES.items():
        directory = os.path.join(target, name)
        os.makedirs(directory, exist_ok=True)
        config, required = build(name, spec)
        with open(
            os.path.join(directory, "nfqws2.conf"),
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(config)
        with open(
            os.path.join(directory, "required-blobs.txt"),
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write("\n".join(required) + "\n")
        print(f"[{name}] {len(config)} Б, блобов: {len(required)}")


if __name__ == "__main__":
    main()
