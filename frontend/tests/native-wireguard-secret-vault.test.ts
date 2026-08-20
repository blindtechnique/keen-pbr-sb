import { describe, expect, test } from "bun:test"

import { createNativeWireGuardSecretVault } from "@/lib/native-wireguard-secret-vault"

const bytes = (...values: number[]) => new Uint8Array(values)

describe("native WireGuard one-shot secret vault", () => {
  test("replaces and wipes the previous retained secret", () => {
    const vault = createNativeWireGuardSecretVault()
    const ticket = vault.begin()
    const first = bytes(1, 2, 3)
    const second = bytes(4, 5)

    expect(vault.replace(ticket, first)).toBe(true)
    expect(first).toEqual(bytes(0, 0, 0))
    expect(vault.replace(ticket, second)).toBe(true)
    expect(second).toEqual(bytes(0, 0))

    expect(vault.takeOnce(ticket)).toEqual(bytes(4, 5))
  })

  test("wipes caller bytes even when the private copy cannot be allocated", () => {
    const vault = createNativeWireGuardSecretVault({
      copySecret: () => {
        throw new RangeError("allocation failed")
      },
    })
    const ticket = vault.begin()
    const secret = bytes(21, 22, 23)

    expect(() => vault.replace(ticket, secret)).toThrow("allocation failed")
    expect(secret).toEqual(bytes(0, 0, 0))
    expect(vault.takeOnce(ticket)).toBeNull()
  })

  test("wipes private copies on replacement, clear, revoke and dispose", () => {
    const copies: Uint8Array[] = []
    const vault = createNativeWireGuardSecretVault({
      copySecret: (secret) => {
        const copy = new Uint8Array(secret)
        copies.push(copy)
        return copy
      },
    })

    const replaced = vault.begin()
    expect(vault.replace(replaced, bytes(1))).toBe(true)
    expect(vault.replace(replaced, bytes(2, 3))).toBe(true)
    expect(copies[0]).toEqual(bytes(0))

    vault.clear()
    expect(copies[1]).toEqual(bytes(0, 0))

    const revoked = vault.begin()
    expect(vault.replace(revoked, bytes(4))).toBe(true)
    vault.revoke()
    expect(copies[2]).toEqual(bytes(0))

    const disposed = vault.begin()
    expect(vault.replace(disposed, bytes(5))).toBe(true)
    vault.dispose()
    expect(copies[3]).toEqual(bytes(0))
  })

  test("transfers a secret only once", () => {
    const vault = createNativeWireGuardSecretVault()
    const ticket = vault.begin()
    expect(vault.replace(ticket, bytes(7, 8))).toBe(true)

    const taken = vault.takeOnce(ticket)
    expect(taken).toEqual(bytes(7, 8))
    expect(vault.takeOnce(ticket)).toBeNull()
  })

  test("clear wipes retained bytes and invalidates the ticket", () => {
    const vault = createNativeWireGuardSecretVault()
    const ticket = vault.begin()
    expect(vault.replace(ticket, bytes(9, 10))).toBe(true)

    vault.clear()

    expect(vault.takeOnce(ticket)).toBeNull()
    expect(vault.replace(ticket, bytes(11))).toBe(false)
  })

  test("a stale asynchronous selection cannot overwrite or consume the new one", () => {
    const vault = createNativeWireGuardSecretVault()
    const stale = vault.begin()
    expect(vault.replace(stale, bytes(1))).toBe(true)

    const current = vault.begin()
    expect(vault.replace(current, bytes(2))).toBe(true)
    const rejected = bytes(3, 4)

    expect(vault.replace(stale, rejected)).toBe(false)
    expect(rejected).toEqual(bytes(0, 0))
    expect(vault.takeOnce(stale)).toBeNull()
    expect(vault.takeOnce(current)).toEqual(bytes(2))
  })

  test("revocation clears current authority but permits a fresh selection", () => {
    const vault = createNativeWireGuardSecretVault()
    const revoked = vault.begin()
    expect(vault.replace(revoked, bytes(5))).toBe(true)

    vault.revoke()

    expect(vault.takeOnce(revoked)).toBeNull()
    const fresh = vault.begin()
    expect(vault.replace(fresh, bytes(6))).toBe(true)
    expect(vault.takeOnce(fresh)).toEqual(bytes(6))
  })

  test("dispose models unmount and cannot be resurrected by late callbacks", () => {
    const vault = createNativeWireGuardSecretVault()
    const beforeUnmount = vault.begin()
    expect(vault.replace(beforeUnmount, bytes(12))).toBe(true)

    vault.dispose()

    expect(vault.takeOnce(beforeUnmount)).toBeNull()
    const lateTicket = vault.begin()
    const lateBytes = bytes(13, 14)
    expect(vault.replace(lateTicket, lateBytes)).toBe(false)
    expect(lateBytes).toEqual(bytes(0, 0))
    expect(vault.takeOnce(lateTicket)).toBeNull()
  })
})
