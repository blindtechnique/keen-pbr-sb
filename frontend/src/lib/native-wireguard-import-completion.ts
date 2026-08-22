export type NativeWireGuardImportedIdentity = Readonly<{
  firmwareInterface: string
  kernelInterface: string
  kind: "wireguard" | "amnezia_wireguard"
}>

type ActiveImportCompletionHandler = (
  identity: NativeWireGuardImportedIdentity
) => boolean

let activeHandler:
  | Readonly<{
      token: symbol
      handle: ActiveImportCompletionHandler
    }>
  | undefined

/**
 * The import dialog and the page-level bodyless recovery worker live in
 * separate React branches. Keep a same-document hand-off so a recovery that
 * finishes while the dialog is still open can use the alias/country already
 * entered there. Nothing is persisted and a reload deliberately falls back to
 * the inventory-derived tracker.
 */
export function registerActiveNativeWireGuardImportCompletion(
  handle: ActiveImportCompletionHandler
): () => void {
  const token = Symbol("native-wireguard-import-completion")
  activeHandler = { token, handle }
  return () => {
    if (activeHandler?.token === token) activeHandler = undefined
  }
}

export function offerNativeWireGuardImportCompletion(
  identity: NativeWireGuardImportedIdentity
): boolean {
  return activeHandler?.handle(identity) === true
}
