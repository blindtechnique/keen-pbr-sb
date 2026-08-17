"use client"

import { useCallback, useEffect, useRef, useState } from "react"

import {
  subscribeDnsProbeEvents,
  type DnsProbeEvent,
} from "@/api/dns-probe-events"
import {
  acquireStatusEventKeepAliveLease,
  getStatusEventConnectionState,
  subscribeStatusEventConnectionState,
} from "@/api/status-event-connection"

export type DnsCheckStatus =
  | "idle"
  | "checking"
  | "success"
  | "browser-fail"
  | "sse-fail"
  | "pc-success"

type DnsCheckState = {
  randomString: string
  waiting: boolean
  showWarning: boolean
}

type UseDnsCheckReturn = {
  status: DnsCheckStatus
  checkState: DnsCheckState
  startCheck: (performBrowserRequest: boolean) => void
  reset: () => void
}

export const DNS_CHECK_DOMAIN_SUFFIX = "check.keen.pbr"

const browserCheckTimeoutMs = 5_000
const sseConnectionTimeoutMs = 12_000
const pcCheckTimeoutMs = 300_000
const pcWarningTimeoutMs = 30_000

export function useDnsCheck(): UseDnsCheckReturn {
  const dnsSubscriptionRef = useRef<(() => void) | null>(null)
  const connectionSubscriptionRef = useRef<(() => void) | null>(null)
  const keepAliveLeaseRef = useRef<(() => void) | null>(null)
  const fetchControllerRef = useRef<AbortController | null>(null)
  const checkTimeoutRef = useRef<number | null>(null)
  const warningTimeoutRef = useRef<number | null>(null)

  const [status, setStatus] = useState<DnsCheckStatus>("idle")
  const [checkState, setCheckState] = useState<DnsCheckState>({
    randomString: "",
    waiting: false,
    showWarning: false,
  })

  const cleanup = useCallback(() => {
    dnsSubscriptionRef.current?.()
    dnsSubscriptionRef.current = null
    connectionSubscriptionRef.current?.()
    connectionSubscriptionRef.current = null
    keepAliveLeaseRef.current?.()
    keepAliveLeaseRef.current = null

    if (fetchControllerRef.current) {
      fetchControllerRef.current.abort()
      fetchControllerRef.current = null
    }

    if (checkTimeoutRef.current !== null) {
      window.clearTimeout(checkTimeoutRef.current)
      checkTimeoutRef.current = null
    }

    if (warningTimeoutRef.current !== null) {
      window.clearTimeout(warningTimeoutRef.current)
      warningTimeoutRef.current = null
    }
  }, [])

  useEffect(() => cleanup, [cleanup])

  const startCheck = useCallback(
    (performBrowserRequest: boolean) => {
      cleanup()

      const randomString = Math.random().toString(36).slice(2, 15)
      const domain = `${randomString}.${DNS_CHECK_DOMAIN_SUFFIX}`

      setCheckState({
        randomString,
        waiting: !performBrowserRequest,
        showWarning: false,
      })
      setStatus("checking")
      keepAliveLeaseRef.current = acquireStatusEventKeepAliveLease()

      if (!performBrowserRequest) {
        warningTimeoutRef.current = window.setTimeout(() => {
          setCheckState((current) => ({ ...current, showWarning: true }))
        }, pcWarningTimeoutMs)
      }

      let sseConnected = false
      const finishTimedOutCheck = () => {
        cleanup()

        if (!sseConnected) {
          setStatus("sse-fail")
          return
        }

        if (performBrowserRequest) {
          setStatus("browser-fail")
          return
        }

        setCheckState((current) => ({
          ...current,
          waiting: false,
          showWarning: true,
        }))
      }

      dnsSubscriptionRef.current = subscribeDnsProbeEvents(
        (payload: DnsProbeEvent) => {
          if (payload.domain !== domain) return

          cleanup()
          setCheckState((current) => ({
            ...current,
            waiting: false,
            showWarning: false,
          }))
          setStatus(performBrowserRequest ? "success" : "pc-success")
        }
      )

      const beginCheckWhenConnected = () => {
        if (
          sseConnected ||
          getStatusEventConnectionState() !== "connected"
        ) {
          return
        }

        sseConnected = true
        connectionSubscriptionRef.current?.()
        connectionSubscriptionRef.current = null
        if (checkTimeoutRef.current !== null) {
          window.clearTimeout(checkTimeoutRef.current)
        }
        checkTimeoutRef.current = window.setTimeout(
          finishTimedOutCheck,
          performBrowserRequest ? browserCheckTimeoutMs : pcCheckTimeoutMs
        )

        if (performBrowserRequest) {
          fetchControllerRef.current = new AbortController()
          fetch(`https://${domain}`, {
            signal: fetchControllerRef.current.signal,
            mode: "no-cors",
          }).catch((error: unknown) => {
            if (
              error &&
              typeof error === "object" &&
              "name" in error &&
              error.name === "AbortError"
            ) {
              return
            }
          })
        }
      }

      checkTimeoutRef.current = window.setTimeout(
        finishTimedOutCheck,
        sseConnectionTimeoutMs
      )
      connectionSubscriptionRef.current =
        subscribeStatusEventConnectionState(beginCheckWhenConnected)
      beginCheckWhenConnected()
    },
    [cleanup]
  )

  const reset = useCallback(() => {
    cleanup()
    setStatus("idle")
    setCheckState({
      randomString: "",
      waiting: false,
      showWarning: false,
    })
  }, [cleanup])

  return {
    status,
    checkState,
    startCheck,
    reset,
  }
}
