#!/usr/bin/env python3
"""
Генератор пресетов nfqws2 для keen-pbr-sb.

Единый источник правды: все профили собираются отсюда, поэтому инварианты
(IPV6_ENABLED, соответствие filter-* и *_PORTS, key=/inseq= у каждого circular,
required-blobs.txt) не могут разъехаться между файлами.

Запуск:  python3 build_scripts/build-nfqws-strategies.py <каталог-назначения>
"""
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

# ─────────────────────────────────────────────────────────────────────────────
# Тиры TCP (общий пул). Каждый тир — список действий без :strategy=N,
# номер проставляется при сборке.
# ─────────────────────────────────────────────────────────────────────────────

TCP_TIERS = [
    # 1-5 — наши тиры, проверенные в ver9/ver10, оставлены без изменений
    ["fake:blob=tls_clienthello:optional:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000",
     "multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up"],

    ["fake:blob=tls_clienthello:optional:tcp_ack=-66000:tls_mod=rnd,dupsid,sni=www.google.com:tcp_ts_up:repeats=2",
     "multisplit:pos=1,midsld"],

    ["hostfakesplit:host=ozon.ru:midhost=host-2:seqovl=sniext+3:seqovl_pattern=tls_clienthello:badsum:tcp_md5:tcp_ts_up",
     "hostfakesplit:tcp_md5:tcp_ts_up"],

    ["multidisorder:pos=1,midsld:seqovl=3:seqovl_pattern=tls_clienthello:tcp_ts_up"],

    ["fake:blob=tls_clienthello:optional:tls_mod=rnd,dupsid,sni=www.microsoft.com:tcp_seq=10000:ip_autottl=1,3-12",
     "multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up"],

    # 6-8 — наши тиры из ver10, тир 8 с ИСПРАВЛЕННЫМ max.ru
    ["multisplit:pos=2:seqovl=681:seqovl_pattern=tls_google:optional"],

    ["fake:blob=stun_fake:optional:tcp_seq=10000:repeats=6",
     "multisplit:pos=2,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up"],

    ["fake:blob=tls_max:optional:tcp_ack=-66000:tcp_ts_up:repeats=2",
     "fake:blob=tls_4pda:optional:tcp_ack=-66000:tcp_ts_up",
     "multisplit:pos=2,midsld:tcp_ts_up"],

    # 9-12 — заимствованы у z2k, все техники нативные для zapret2.
    # seqovl подобран под точный размер блоба: onetrust=664 Б, activated=655 Б.
    ["fake:blob=tls_onetrust:optional:repeats=8:badseq:badsum:badseq_increment=0",
     "multisplit:pos=1:seqovl=664:seqovl_pattern=tls_onetrust:optional"],

    ["fake:blob=tls_activated:optional:repeats=8:badseq:badsum:badseq_increment=0",
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
    ["fake:blob=tls_google:optional:tls_mod=rnd,dupsid,sni=ggpht.com:badsum:badseq",
     "multisplit:pos=2,sld:seqovl=620:seqovl_pattern=tls_google:optional"],
    ["fake:blob=tls_onetrust:optional:repeats=8:badseq:badsum",
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

# ─────────────────────────────────────────────────────────────────────────────
# Профили
# ─────────────────────────────────────────────────────────────────────────────

PROFILES = {
    "01 safe": dict(
        title="БЕЗОПАСНЫЙ",
        note=("Ровно то же поведение, что у прежних пресетов, но без их дефектов. "
              "Один общий пул на протокол, без отдельных пулов под YouTube и Discord, "
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
        note=("Всё из обычного плюс четыре дополнительных тира TCP (включая syndata — "
              "данные в SYN), фрагментация IP и подмена оригинала в QUIC. "
              "Экспериментальный: часть провайдеров и часть серверов на syndata реагируют "
              "разрывом. Ставьте, только если обычный не справляется."),
        tcp=12, quic=6, udp=4, custom=True, http_fake=True,
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


def circular(key, *, inseq=None, retrans=2, udp=False, maxseq=None):
    """circular с обязательным key= (стабильное пространство состояний)."""
    parts = ["fails=2", "time=300"]
    if udp:
        parts += ["udp_in=1", "udp_out=4"]
    else:
        parts += [f"retrans={retrans}"]
        if inseq:
            parts.append(f"inseq={inseq}")
        if maxseq:
            parts.append(f"maxseq={maxseq}")
    parts += ["nld=2", f"key={key}"]
    return "--lua-desync=circular:" + ":".join(parts)


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

    base_pool = pool(TCP_TIERS, tcp_n)
    quic_pool = pool(QUIC_TIERS, quic_n)
    udp_pool = pool(UDP_TIERS, udp_n)

    # ── NFQWS_ARGS: общий TCP-пул (РКН и всё остальное) ──────────────────────
    args = [f"--filter-tcp={FILTER_TCP}", "--filter-l7=http,tls,mtproto",
            "--payload=tls_client_hello,mtproto_initial",
            circular("tcp_general", inseq=26000, maxseq=65536)] + base_pool
    args += ["--payload=http_req"]
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

        # ВАЖНО про --new. Init-скрипт собирает строку как
        #   ... $NFQWS_BASE_ARGS $NFQWS_ARGS_CUSTOM --new $NFQWS_ARGS ... --new $NFQWS_ARGS_QUIC ...
        # то есть перед CUSTOM разделителя НЕТ (первый блок делит профиль с BASE_ARGS,
        # а там только --lua-init и --blob, они глобальные), и --new ставится ПОСЛЕ секции.
        # Поэтому первый блок идёт без имени, а каждый следующий начинается с --new=<имя>.
        # Ставить --new внутри NFQWS_ARGS/_QUIC/_UDP/_IPSET/_BASE_ARGS нельзя:
        # validate_config() в init-скрипте на это прерывает запуск.
        blocks = [
            # googlevideo идёт раньше youtube: он специфичнее
            [f"--filter-tcp={FILTER_TCP}", "--filter-l7=tls",
             f"--hostlist-domains={GV_DOMAINS}", excl,
             "--payload=tls_client_hello",
             circular("gv_tcp", inseq=24000, retrans=2, maxseq=65536)] + pool(GV_TCP_TIERS, gv_n),

            ["--new=yt_tcp", f"--filter-tcp={FILTER_TCP}", "--filter-l7=tls",
             f"--hostlist-domains={YT_DOMAINS}", excl,
             "--payload=tls_client_hello",
             circular("yt_tcp", inseq=18000, retrans=2, maxseq=65536)] + pool(YT_TCP_TIERS, yt_n),

            ["--new=yt_quic", "--filter-udp=443", "--filter-l7=quic",
             f"--hostlist-domains={YT_DOMAINS},{GV_DOMAINS}", excl,
             "--payload=quic_initial",
             circular("yt_quic", udp=True)] + pool(YT_QUIC_TIERS, yq_n),

            ["--new=discord_udp", "--filter-udp=50000-50099,3478-3481,5349,19294-19344",
             "--filter-l7=discord,stun", "--out-range=<n2",
             "--payload=discord_ip_discovery,stun",
             circular("discord_udp", udp=True)] + pool(DISCORD_TIERS, dc_n),

            # сквозной пропуск WebRTC P2P: профиль без единого --lua-desync
            ["--new=webrtc_passthrough", "--filter-udp=49152-65535", "--filter-l7=stun"],
        ]
        for block in blocks:
            custom += block

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

    tiers_note = (f"TCP {tcp_n} · QUIC {quic_n} · UDP {udp_n}"
                  + (" · отдельные пулы: googlevideo, youtube, youtube-QUIC, discord, "
                     "сквозной WebRTC" if spec["custom"] else " · без отдельных пулов"))

    head = "\n".join([
        f"# keen-pbr-sb · профиль «{spec['title']}»",
        "#",
        *[f"# {line}" for line in _wrap_text(spec["note"], 88)],
        "#",
        f"# Глубина пулов: {tiers_note}",
        "# Пулы разделены по группам доменов: у каждого свой circular со своим key=.",
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
            "# Списки режимов (user.list/auto.list) сюда не подставляются — у каждого",
            "# пула свой --hostlist-domains, но общий exclude.list уважается.",
            wrap("NFQWS_ARGS_CUSTOM", custom, indent=19),
            "",
        ]
    else:
        body += ['NFQWS_ARGS_CUSTOM=""', ""]

    body += [
        "# Режимы работы, не менять",
        f'MODE_LIST="--hostlist={LISTS}/user.list"',
        f'MODE_ALL="--hostlist-exclude={LISTS}/exclude.list"',
        f'MODE_AUTO="$MODE_LIST --hostlist-auto={LISTS}/auto.list '
        f'--hostlist-auto-debug=/opt/var/log/nfqws2.log $MODE_ALL"',
        "",
        "# $MODE_AUTO — сам находит заблокированные домены и дописывает в auto.list",
        "# $MODE_LIST — только домены из user.list",
        "# $MODE_ALL  — весь трафик, кроме exclude.list",
        'NFQWS_EXTRA_ARGS="$MODE_AUTO"',
        "",
        "# IP-списки",
        f'NFQWS_ARGS_IPSET="--ipset={LISTS}/ipset.list --ipset-exclude={LISTS}/ipset_exclude.list"',
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
