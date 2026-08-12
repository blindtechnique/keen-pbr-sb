import { describe, expect, test } from "bun:test"

import {
  canonicalNfqwsProfileTier,
  nfqwsBuiltinStrategyDisplayKey,
  parseNfqwsProfileMarker,
  parseNfqwsStrategy,
  parseShellAssignments,
} from "../src/pages/nfqws-strategy-model"

const SAMPLE = `# a real strategy-shaped subset
NFQWS_BASE_ARGS="--lua-init=@/x.lua --blob=quic:@/q.bin --blob=tls:@/t.bin"
NFQWS_ARGS="--filter-tcp=443,80 --filter-l7=http,tls
  --lua-desync=circular:fails=2:time=300:retrans=3:inseq=26000:key=tcp_general
  --lua-desync=fake:blob=tls:strategy=1
  --lua-desync=multisplit:pos=1:strategy=2
  --lua-desync=multidisorder:pos=1:strategy=3"
NFQWS_ARGS_QUIC="--filter-udp=443 --filter-l7=quic
  --lua-desync=circular:fails=2:key=quic_general
  --lua-desync=fake:blob=quic:strategy=1
  --lua-desync=send:ipfrag:strategy=2
  --lua-desync=drop:strategy=2"
NFQWS_ARGS_CUSTOM="--filter-tcp=443 --filter-l7=tls
  --hostlist-domains=youtube.com,youtu.be
  --lua-desync=circular:fails=2:inseq=18000:key=yt_tcp
  --lua-desync=fake:blob=tls:strategy=1
  --new=yt_quic --filter-udp=443 --filter-l7=quic
  --hostlist-domains=youtube.com
  --lua-desync=circular:fails=2:key=yt_quic
  --lua-desync=fake:blob=quic:strategy=1
  --new=webrtc_passthrough --filter-udp=49152-65535 --filter-l7=stun"
NFQWS_ARGS_IPSET="--ipset=/opt/etc/nfqws2/lists/ipset.list"`

describe("safe shell assignment subset", () => {
  test("reads multiline canonical values and expands prior simple variables", () => {
    const parsed = parseShellAssignments(`
COMMON='--filter-tcp=443 --filter-l7=tls'
NFQWS_ARGS="$COMMON --lua-desync=fake:strategy=1"
NFQWS_ARGS_QUIC='--filter-udp=443 --lua-desync=fake:strategy=1'
`)

    expect(parsed.has("COMMON")).toBe(false)
    expect(parsed.get("NFQWS_ARGS")).toContain("--filter-tcp=443")
    expect(parsed.get("NFQWS_ARGS_QUIC")).toContain("--filter-udp=443")
  })

  test("is line anchored and exposes canonical variable names only", () => {
    const parsed = parseShellAssignments(`
echo NFQWS_ARGS="--lua-desync=fake:strategy=9"
NFQWS_ARGS_EXTRA="--filter-tcp=80 --lua-desync=fake:strategy=8"
NFQWS_ARGS="--filter-tcp=443 --lua-desync=fake:strategy=1"
`)

    expect(parsed.has("NFQWS_ARGS_EXTRA")).toBe(false)
    expect(parsed.get("NFQWS_ARGS")).not.toContain("strategy=9")
    expect(parsed.get("NFQWS_ARGS")).toContain("strategy=1")
  })

  test("honours safe quote and escape rules without expanding escaped dollars", () => {
    const parsed = parseShellAssignments(`
LITERAL='not expanded'
NFQWS_ARGS="--filter-tcp=443 --filter-l7=\\"tls\\" \\$LITERAL --lua-desync=fake:strategy=1"
`)

    expect(parsed.get("NFQWS_ARGS")).toContain('--filter-l7="tls"')
    expect(parsed.get("NFQWS_ARGS")).toContain("$LITERAL")
    expect(
      parseNfqwsStrategy(
        `NFQWS_ARGS='--filter-tcp=443 --lua-desync=fake:strategy=1'`
      ).status
    ).toBe("complete")
  })

  test("does not use forward references or command substitutions", () => {
    const forward = parseNfqwsStrategy(`
NFQWS_ARGS="$LATER"
LATER='--filter-tcp=443 --lua-desync=fake:strategy=1'
`)
    const command = parseNfqwsStrategy(
      'NFQWS_ARGS="$(touch /tmp/never) --filter-tcp=443 --lua-desync=fake:strategy=1"'
    )
    const backticks = parseNfqwsStrategy(
      'NFQWS_ARGS="`touch /tmp/never` --filter-tcp=443 --lua-desync=fake:strategy=1"'
    )

    expect(forward.status).toBe("incomplete")
    expect(command.status).toBe("incomplete")
    expect(backticks.status).toBe("incomplete")
    expect(command.pools).toHaveLength(0)
  })

  test("rejects every shell expansion outside the simple prior $VAR subset", () => {
    const unsupported = [
      'NFQWS_ARGS="${LATER} --filter-tcp=443 --lua-desync=fake:strategy=1"',
      "NFQWS_ARGS=$'--filter-tcp=443 --lua-desync=fake:strategy=1'",
      'NFQWS_ARGS="$[1+1] --filter-tcp=443 --lua-desync=fake:strategy=1"',
    ]

    for (const source of unsupported) {
      expect(parseNfqwsStrategy(source).status).toBe("incomplete")
    }
  })

  test("does not reinterpret shell-invalid spacing as an assignment", () => {
    const beforeEquals = parseNfqwsStrategy(
      'NFQWS_ARGS ="--filter-tcp=443 --lua-desync=fake:strategy=1"'
    )
    const afterEquals = parseNfqwsStrategy(
      'NFQWS_ARGS= "--filter-tcp=443 --lua-desync=fake:strategy=1"'
    )

    expect(beforeEquals.status).toBe("incomplete")
    expect(afterEquals.status).toBe("incomplete")
  })

  test("rejects a trailing shell command but accepts literal text in single quotes", () => {
    const trailing = parseNfqwsStrategy(
      'NFQWS_ARGS="--filter-tcp=443 --lua-desync=fake:strategy=1" ; touch /tmp/never'
    )
    const literal = parseNfqwsStrategy(
      "NFQWS_ARGS='--filter-tcp=443 --lua-desync=fake:note=$(literal):strategy=1'"
    )

    expect(trailing.status).toBe("incomplete")
    expect(literal.status).toBe("complete")
    expect(literal.pools).toHaveLength(1)
  })
})

describe("nfqws strategy breakdown", () => {
  const summary = parseNfqwsStrategy(SAMPLE)

  test("parses the complete sample and counts canonical blobs", () => {
    expect(summary.status).toBe("complete")
    expect(summary.blobCount).toBe(2)
    expect(summary.pools).toHaveLength(5)
    expect(summary.pools.map((pool) => pool.varName)).not.toContain(
      "NFQWS_ARGS_IPSET"
    )
  })

  test("counts distinct strategy ids rather than techniques", () => {
    const tcp = summary.pools.find((pool) => pool.varName === "NFQWS_ARGS")
    const quic = summary.pools.find(
      (pool) => pool.varName === "NFQWS_ARGS_QUIC"
    )

    expect(tcp?.rotation?.slots).toBe(3)
    expect(quic?.techniques).toEqual(["fake", "send", "drop"])
    expect(quic?.rotation?.slots).toBe(2)
  })

  test("falls back to one rotation slot when actions have no id", () => {
    const parsed = parseNfqwsStrategy(`
NFQWS_ARGS="--filter-tcp=443
  --lua-desync=circular:fails=2
  --lua-desync=fake:blob=tls
  --lua-desync=multisplit:pos=1"
`)

    expect(parsed.pools[0]?.techniques).toEqual(["fake", "multisplit"])
    expect(parsed.pools[0]?.rotation?.slots).toBe(1)
  })

  test("splits named and unnamed profiles only inside CUSTOM", () => {
    const parsed = parseNfqwsStrategy(`
NFQWS_ARGS="--filter-tcp=443 --lua-desync=fake:strategy=1 --new=not_a_split --lua-desync=multisplit:strategy=2"
NFQWS_ARGS_CUSTOM="--new=first --filter-tcp=80 --lua-desync=fake:strategy=1 --new --filter-udp=443 --lua-desync=fake:strategy=1"
`)

    expect(
      parsed.pools.filter((pool) => pool.varName === "NFQWS_ARGS")
    ).toHaveLength(1)
    expect(
      parsed.pools.filter((pool) => pool.varName === "NFQWS_ARGS_CUSTOM")
    ).toHaveLength(2)
    expect(parsed.pools.find((pool) => pool.name === "first")).toBeDefined()
  })

  test("shows only the exact approved WebRTC filter-only segment", () => {
    const approved = summary.pools.find(
      (pool) => pool.name === "webrtc_passthrough"
    )
    const altered = parseNfqwsStrategy(`
NFQWS_ARGS_CUSTOM="--filter-tcp=443 --lua-desync=fake:strategy=1
  --new=webrtc_passthrough --filter-udp=49152-65535 --filter-l7=stun --payload=stun"
`)

    expect(approved).toMatchObject({
      filterOnly: true,
      transport: "udp",
      udpPorts: "49152-65535",
      protocols: ["stun"],
    })
    expect(
      altered.pools.some((pool) => pool.name === "webrtc_passthrough")
    ).toBe(false)
    expect(altered.status).toBe("partial")
  })

  test("does not guess one transport when both filters are present", () => {
    const parsed = parseNfqwsStrategy(
      'NFQWS_ARGS="--filter-tcp=443 --filter-udp=443 --lua-desync=fake:strategy=1"'
    )

    expect(parsed.pools[0]).toMatchObject({
      transport: "unknown",
      tcpPorts: "443",
      udpPorts: "443",
    })
  })

  test("reports partial and incomplete input without inventing pools", () => {
    const partial = parseNfqwsStrategy(`
NFQWS_ARGS="--filter-tcp=443 --lua-desync=fake:strategy=1"
NFQWS_ARGS_QUIC="$(unsafe)"
`)
    const incomplete = parseNfqwsStrategy("just some shell text")

    expect(partial.status).toBe("partial")
    expect(partial.pools).toHaveLength(1)
    expect(incomplete.status).toBe("incomplete")
    expect(incomplete.parseable).toBe(false)
  })
})

describe("nfqws profile marker", () => {
  test("maps the three generated first-line markers to ordered tiers", () => {
    expect(
      parseNfqwsProfileMarker("# keen-pbr-sb · профиль «БЕЗОПАСНЫЙ»\n#")
    ).toEqual({ tier: "safe", role: "БЕЗОПАСНЫЙ" })
    expect(
      parseNfqwsProfileMarker("# keen-pbr-sb · профиль «ОБЫЧНЫЙ»\n#")
    ).toEqual({ tier: "balanced", role: "ОБЫЧНЫЙ" })
    expect(
      parseNfqwsProfileMarker("# keen-pbr-sb · профиль «МАКСИМАЛЬНЫЙ»\r\n#")
    ).toEqual({ tier: "max", role: "МАКСИМАЛЬНЫЙ" })
  })

  test("does not promote a marker found later or an unknown role", () => {
    expect(
      parseNfqwsProfileMarker(
        "# custom\n# keen-pbr-sb · профиль «ОБЫЧНЫЙ»\nNFQWS_ARGS=''"
      )
    ).toBeUndefined()
    expect(
      parseNfqwsProfileMarker("# keen-pbr-sb · профиль «ЭКСТРА»\n")
    ).toEqual({ tier: undefined, role: "ЭКСТРА" })
  })

  test("promotes only built-in entries carrying a known marker", () => {
    const content = "# keen-pbr-sb · профиль «ОБЫЧНЫЙ»\n"
    expect(
      canonicalNfqwsProfileTier({
        builtin: true,
        overridden: false,
        canonical: true,
        content,
      })
    ).toBe("balanced")
    expect(
      canonicalNfqwsProfileTier({
        builtin: false,
        overridden: false,
        canonical: false,
        content,
      })
    ).toBeUndefined()
    expect(
      canonicalNfqwsProfileTier({
        builtin: true,
        overridden: false,
        canonical: true,
        content: "# keen-pbr-sb · профиль «ЭКСТРА»\n",
      })
    ).toBeUndefined()
  })

  /**
   * Состояние роутера после «Применить»: backend записывает пользовательскую
   * копию, и профиль возвращается с `overridden: true`, хотя его никто не
   * правил. Пока флаг участвовал в раскладке, только что выбранная карточка
   * исчезала из трёх профилей — то есть выбор сам себя и отменял.
   */
  test("keeps an applied profile on the cards even though it became overridden", () => {
    expect(
      canonicalNfqwsProfileTier({
        builtin: true,
        overridden: true,
        canonical: true,
        content: "# keen-pbr-sb · профиль «ОБЫЧНЫЙ»\n",
      })
    ).toBe("balanced")
  })

  test("does not promote an edited override that retained the profile marker", () => {
    expect(
      canonicalNfqwsProfileTier({
        builtin: true,
        overridden: true,
        canonical: false,
        content: "# keen-pbr-sb · профиль «ОБЫЧНЫЙ»\nNFQWS_ARGS='edited'\n",
      })
    ).toBeUndefined()
  })
})

describe("nfqws legacy strategy display names", () => {
  test("corrects spelling only for the three bundled legacy identifiers", () => {
    expect(
      nfqwsBuiltinStrategyDisplayKey({
        name: "ver5 aggresive",
        builtin: true,
      })
    ).toBe("ver5Aggressive")
    expect(
      nfqwsBuiltinStrategyDisplayKey({
        name: "ver7 more aggresive",
        builtin: true,
      })
    ).toBe("ver7MoreAggressive")
    expect(
      nfqwsBuiltinStrategyDisplayKey({
        name: "ver8 max aggresive",
        builtin: true,
      })
    ).toBe("ver8MostAggressive")
  })

  test("keeps custom and unknown identifiers verbatim", () => {
    expect(
      nfqwsBuiltinStrategyDisplayKey({
        name: "ver5 aggresive",
        builtin: false,
      })
    ).toBeUndefined()
    expect(
      nfqwsBuiltinStrategyDisplayKey({ name: "ver4", builtin: true })
    ).toBeUndefined()
  })
})
