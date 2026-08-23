import {
  getNativeBindBlockReason,
  type NativeInterfaceModel,
} from "@/lib/native-interfaces"

/**
 * Предложение «использовать новый туннель как VPN».
 *
 * keen-pbr-sb не может задать вопрос внутри веб-конфигуратора KeeneticOS в
 * момент создания интерфейса — это чужой интерфейс. Ближайший честный
 * эквивалент: панель сама замечает клиентский туннель без маршрута и
 * спрашивает при первом же открытии. «Да» создаёт маршрут в черновике,
 * «Не предлагать» запоминается для конкретного интерфейса.
 *
 * Отказы хранятся в localStorage браузера, а не в конфигурации: полей под
 * это в схеме ui_preferences пока нет (заметка для Codex в changelog). На
 * другом устройстве вопрос появится снова — это терпимо, ответ «Да» там
 * уже не понадобится.
 */

const DISMISSED_STORAGE_KEY = "keen-pbr-sb.dismissed-native-route-offers"

export interface NativeRouteOfferCandidate {
  readonly id: string
  readonly label: string
  readonly interfaceName: string
}

export function readDismissedNativeRouteOffers(): Set<string> {
  try {
    const raw = window.localStorage.getItem(DISMISSED_STORAGE_KEY)
    if (!raw) {
      return new Set()
    }
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) {
      return new Set()
    }
    return new Set(
      parsed.filter((item): item is string => typeof item === "string")
    )
  } catch {
    return new Set()
  }
}

export function dismissNativeRouteOffer(
  interfaceId: string,
  current: ReadonlySet<string>
): Set<string> {
  const next = new Set(current)
  next.add(interfaceId)
  try {
    window.localStorage.setItem(
      DISMISSED_STORAGE_KEY,
      JSON.stringify([...next].sort())
    )
  } catch {
    // Приватный режим или заполненное хранилище: предложение просто
    // появится при следующем открытии, данных это не портит.
  }
  return next
}

/**
 * Кому предлагать маршрут. Правило доступности то же, что у кнопки в строке
 * туннеля и списка в форме добавления (getNativeBindBlockReason): не сервер
 * и с системным именем. Дополнительно: маршрута ещё нет, интерфейс не скрыт
 * и предложение для него не отклонялось.
 */
export function pickNativeRouteOfferCandidates({
  nativeInterfaces,
  boundInterfaceNames,
  hiddenIds,
  dismissedIds,
}: {
  readonly nativeInterfaces: readonly NativeInterfaceModel[]
  readonly boundInterfaceNames: ReadonlySet<string>
  readonly hiddenIds: ReadonlySet<string>
  readonly dismissedIds: ReadonlySet<string>
}): NativeRouteOfferCandidate[] {
  return nativeInterfaces.flatMap((nativeInterface) => {
    // Imports owned by this panel are completed by the import pipeline itself.
    // This offer is only for a WG/AWG tunnel the operator created directly in
    // KeeneticOS and whose absent panel claim was observed authoritatively.
    if (
      nativeInterface.source.native_mutation.ownership_state !== "foreign" ||
      (nativeInterface.source.kind !== "wireguard" &&
        nativeInterface.source.kind !== "amnezia_wireguard")
    ) {
      return []
    }
    if (getNativeBindBlockReason(nativeInterface) !== undefined) {
      return []
    }
    const interfaceName = nativeInterface.kernelName
    if (!interfaceName || boundInterfaceNames.has(interfaceName)) {
      return []
    }
    if (
      hiddenIds.has(nativeInterface.id) ||
      dismissedIds.has(nativeInterface.id)
    ) {
      return []
    }
    return [
      {
        id: nativeInterface.id,
        label: nativeInterface.label,
        interfaceName,
      },
    ]
  })
}
