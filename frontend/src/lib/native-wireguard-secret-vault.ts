declare const nativeWireGuardSecretTicketBrand: unique symbol

/**
 * Opaque authority for one selected native WireGuard secret.
 *
 * Components should keep the vault itself in a ref and may keep only this
 * ticket in ordinary UI state. A ticket never contains the secret bytes.
 */
export type NativeWireGuardSecretTicket = Readonly<{
  [nativeWireGuardSecretTicketBrand]: true
}>

export type NativeWireGuardSecretBytes = Uint8Array<ArrayBuffer>

export type NativeWireGuardSecretVaultTestHooks = Readonly<{
  copySecret?: (secret: Uint8Array) => NativeWireGuardSecretBytes
}>

export type NativeWireGuardSecretVault = {
  /** Starts a new selection and wipes any secret retained for the old one. */
  begin: () => NativeWireGuardSecretTicket

  /**
   * Replaces the bytes for the current selection.
   *
   * The vault takes ownership of `secret`, copies it into private storage and
   * wipes the caller's buffer even when the ticket is stale. Callers must not
   * use that buffer after passing it here.
   */
  replace: (ticket: NativeWireGuardSecretTicket, secret: Uint8Array) => boolean

  /**
   * Transfers ownership of the retained bytes exactly once.
   *
   * The receiver must wipe the returned buffer after its single use.
   */
  takeOnce: (
    ticket: NativeWireGuardSecretTicket
  ) => NativeWireGuardSecretBytes | null

  /** Wipes the current secret and invalidates its ticket. */
  clear: () => void

  /** Wipes current authority after an authentication/locality revocation. */
  revoke: () => void

  /** Wipes current authority and permanently closes this component vault. */
  dispose: () => void
}

const wipe = (secret: Uint8Array | null) => {
  secret?.fill(0)
}

const createTicket = (): NativeWireGuardSecretTicket =>
  Object.freeze({}) as NativeWireGuardSecretTicket

/**
 * Creates an in-memory, one-shot vault for a secret-bearing native VPN import.
 *
 * The vault deliberately has no subscription or serialisable state surface,
 * so the secret cannot accidentally enter React state, query caches, devtools
 * snapshots or browser storage through this abstraction.
 */
export function createNativeWireGuardSecretVault(
  testHooks: NativeWireGuardSecretVaultTestHooks = {}
): NativeWireGuardSecretVault {
  const copySecret =
    testHooks.copySecret ??
    ((secret: Uint8Array): NativeWireGuardSecretBytes => new Uint8Array(secret))
  let activeTicket: NativeWireGuardSecretTicket | null = null
  let retainedSecret: NativeWireGuardSecretBytes | null = null
  let disposed = false

  const invalidate = () => {
    wipe(retainedSecret)
    retainedSecret = null
    activeTicket = null
  }

  return {
    begin() {
      invalidate()
      if (disposed) {
        // A disposed vault belongs to an unmounted component and cannot be
        // resurrected by a late asynchronous callback.
        return createTicket()
      }

      activeTicket = createTicket()
      return activeTicket
    },

    replace(ticket, secret) {
      const sourceLength = secret.byteLength
      let ownedCopy: NativeWireGuardSecretBytes
      try {
        ownedCopy = copySecret(secret)
      } finally {
        // Wiping the caller's buffer is unconditional, including allocation or
        // species-construction failures while making the private copy.
        wipe(secret)
      }

      if (
        ownedCopy === secret ||
        ownedCopy.buffer === secret.buffer ||
        ownedCopy.byteLength !== sourceLength
      ) {
        wipe(ownedCopy)
        throw new Error("invalid_native_secret_copy")
      }

      if (disposed || ticket !== activeTicket) {
        wipe(ownedCopy)
        return false
      }

      wipe(retainedSecret)
      retainedSecret = ownedCopy
      return true
    },

    takeOnce(ticket) {
      if (disposed || ticket !== activeTicket || retainedSecret === null) {
        return null
      }

      const secret = retainedSecret
      retainedSecret = null
      activeTicket = null
      return secret
    },

    clear() {
      invalidate()
    },

    revoke() {
      invalidate()
    },

    dispose() {
      invalidate()
      disposed = true
    },
  }
}
