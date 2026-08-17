/**
 * Что это за интерфейс, если судить только по имени ядра.
 *
 * Список интерфейсов приходит из ядра и полон имён вроде `apcli0`, `br0`,
 * `nwg2` — новичку они не говорят ничего. Прошивка знает человеческие имена
 * лишь для части интерфейсов; для остальных единственный источник смысла —
 * само имя. Словарь ниже описывает только то, что имя действительно
 * доказывает: `br0` — это мост, но какой из сегментов сети за ним — по имени
 * не узнать, поэтому и не утверждаем.
 *
 * Неизвестное имя честно остаётся без описания.
 */
export type KernelInterfaceKind =
  | "bridge"
  | "ethernet"
  | "firmwareWg"
  | "keenPbr"
  | "ppp"
  | "service"
  | "tun"
  | "wifiAp"
  | "wireguard"
  | "wisp"

const PATTERNS: ReadonlyArray<readonly [RegExp, KernelInterfaceKind]> = [
  // Интерфейсы, которые создаёт сам keen-pbr под изолированные туннели.
  [/^kpbr/i, "keenPbr"],
  [/^br\d+$/i, "bridge"],
  [/^eth\d+(\.\d+)?$/i, "ethernet"],
  // apcli0 / apclii0 — клиент чужой точки доступа (WISP) на MediaTek.
  [/^apclii?\d*$/i, "wisp"],
  // ra0 / rai0 / rax0 — собственные точки доступа Wi-Fi.
  [/^ra[ix]?\d+$/i, "wifiAp"],
  [/^wl\d/i, "wifiAp"],
  // nwg — WireGuard/AmneziaWG, созданный прошивкой KeeneticOS.
  [/^nwg\d+$/i, "firmwareWg"],
  [/^wg\d+$/i, "wireguard"],
  [/^(tun|tap)\d+$/i, "tun"],
  [/^ppp\d+$/i, "ppp"],
  [/^(lo|dummy\d*|ifb\d*|teql\d*|sit\d+|ip6tnl\d+|ip6gre\d+|gre\d+|gretap\d+)$/i, "service"],
]

export function kernelInterfaceKind(
  name: string
): KernelInterfaceKind | undefined {
  const trimmed = name.trim()
  if (!trimmed) {
    return undefined
  }

  for (const [pattern, kind] of PATTERNS) {
    if (pattern.test(trimmed)) {
      return kind
    }
  }

  return undefined
}
