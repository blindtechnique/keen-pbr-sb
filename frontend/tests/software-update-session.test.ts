import { describe, expect, test } from "bun:test"
import {
  loadUpdateAttempt,
  newUpdateAttempt,
  observeUpdateProgress,
  parseUpdateProgress,
  saveUpdateAttempt,
  updateAttemptNotice,
  updateHttpStatus,
  UPDATE_SESSION_KEY,
  type UpdateProgress,
} from "../src/components/settings/software-update-session"

function storage() {
  const values = new Map<string, string>()
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => {
      values.set(key, value)
    },
    removeItem: (key: string) => {
      values.delete(key)
    },
  }
}
const completed = (updated_at?: number): UpdateProgress => ({
  running: false,
  log: "done",
  phase: "completed",
  percent: 100,
  success: true,
  updated_at,
})
const running = (updated_at?: number): UpdateProgress => ({
  running: true,
  log: "private diagnostic log",
  phase: "installing",
  percent: 40,
  success: null,
  updated_at,
})

describe("software update attempt lifecycle", () => {
  test("accepted → 40% → connection loss → auth remount → verified completion", () => {
    const saved = storage()
    const original = {
      ...newUpdateAttempt("update", "3.3.2-20260910120000", 100, 1_000),
      accepted: true,
    }
    const first = observeUpdateProgress(original, running(101))
    expect(first.apply).toBe(true)
    expect(first.terminal).toBe(false)
    expect(first.attempt.percent).toBe(40)
    expect(updateAttemptNotice(first.attempt, 2_000)).toBe("reconnecting")
    saveUpdateAttempt(saved, first.attempt)
    const restored = loadUpdateAttempt(saved)!
    expect(restored).toEqual(first.attempt)
    // Reauthentication changes neither admission nor the last observed phase.
    expect(updateHttpStatus({ status: 401 })).toBe(401)
    expect(restored.percent).toBe(40)
    const result = observeUpdateProgress(restored, completed(102))
    expect(result.terminal).toBe(true)
    saveUpdateAttempt(saved, null)
    expect(loadUpdateAttempt(saved)).toBeNull()
  })

  test("only whitelisted non-secret metadata is persisted", () => {
    const saved = storage()
    const attempt = newUpdateAttempt(
      "update",
      "3.3.2-20260910120000",
      100,
      1_000
    )
    saveUpdateAttempt(saved, {
      ...attempt,
      log: "SECRET_LOG",
      password: "SECRET_PASSWORD",
      config: { secret: "SECRET_CONFIG" },
    } as typeof attempt)
    const raw = saved.getItem(UPDATE_SESSION_KEY)!
    expect(raw).not.toContain("SECRET")
    expect(Object.keys(JSON.parse(raw)).sort()).toEqual(
      Object.keys(attempt).sort()
    )
    saved.setItem(
      UPDATE_SESSION_KEY,
      JSON.stringify({ ...attempt, password: "injected" })
    )
    expect(loadUpdateAttempt(saved)).toEqual(attempt)
  })

  test("corrupt/unavailable storage never prevents an operation", () => {
    const saved = storage()
    saved.setItem(UPDATE_SESSION_KEY, "not json")
    expect(loadUpdateAttempt(saved)).toBeNull()
    saved.setItem(UPDATE_SESSION_KEY, JSON.stringify({ id: "missing-fields" }))
    expect(loadUpdateAttempt(saved)).toBeNull()
    const blocked = {
      getItem() {
        throw new Error()
      },
      setItem() {
        throw new Error()
      },
      removeItem() {
        throw new Error()
      },
    }
    expect(loadUpdateAttempt(blocked)).toBeNull()
    expect(() =>
      saveUpdateAttempt(blocked, newUpdateAttempt("rollback", "", undefined))
    ).not.toThrow()
    expect(() => saveUpdateAttempt(blocked, null)).not.toThrow()
  })

  test("accepted POST cannot claim an old terminal file as this attempt's success", () => {
    const attempt = {
      ...newUpdateAttempt("update", "3.3.2-new", 100),
      accepted: true,
    }
    for (const progress of [completed(100), completed(99), completed()]) {
      const result = observeUpdateProgress(attempt, progress)
      expect(result.apply).toBe(false)
      expect(result.terminal).toBe(false)
    }
    expect(observeUpdateProgress(attempt, completed(101)).terminal).toBe(true)
  })

  test("an ambiguous POST is not a failure and can be reconciled by GET", () => {
    const attempt = newUpdateAttempt("update", "3.3.2-new", 100, 1_000)
    expect(updateAttemptNotice(attempt, 2_000)).toBe("admissionUnknown")
    expect(observeUpdateProgress(attempt, completed(100)).apply).toBe(false)
    const observed = observeUpdateProgress(attempt, running(101))
    expect(observed.attempt.accepted).toBe(true)
    expect(updateAttemptNotice(observed.attempt, 2_000)).toBe("reconnecting")
  })

  test("a lock paired with the old completed/failed file is not fresh running evidence", () => {
    const attempt = newUpdateAttempt("update", "", undefined)
    for (const progress of [
      { ...completed(101), running: true },
      { ...completed(101), running: true, phase: "failed", success: false },
    ]) {
      const result = observeUpdateProgress(attempt, progress)
      expect(result.apply).toBe(false)
      expect(result.attempt.observedRunning).toBe(false)
      expect(
        observeUpdateProgress(result.attempt, completed(101)).terminal
      ).toBe(false)
    }
  })

  test("legacy responses require observed nonterminal running before terminal success", () => {
    const attempt = {
      ...newUpdateAttempt("rollback", "", undefined),
      accepted: true,
    }
    expect(observeUpdateProgress(attempt, completed()).terminal).toBe(false)
    const observed = observeUpdateProgress(attempt, running()).attempt
    expect(observeUpdateProgress(observed, completed()).terminal).toBe(true)
  })

  test("a real new failed state remains terminal and old responses cannot regress progress", () => {
    const attempt = newUpdateAttempt("update", "", 100)
    const observed = observeUpdateProgress(attempt, running(105)).attempt
    expect(observeUpdateProgress(observed, running(104)).apply).toBe(false)
    expect(observeUpdateProgress(observed, completed(102)).terminal).toBe(false)
    const failed = observeUpdateProgress(observed, {
      running: false,
      log: "package install failed",
      phase: "failed",
      success: false,
      updated_at: 106,
    })
    expect(failed.apply).toBe(true)
    expect(failed.terminal).toBe(true)
    // A legitimate terminal written in the same router-second as fresh running.
    expect(observeUpdateProgress(observed, completed(105)).terminal).toBe(true)
  })

  test("clock skew is irrelevant; timeout and explicit stop do not invent a result", () => {
    const saved = storage()
    const attempt = newUpdateAttempt("update", "", 9_999_999, 1_000)
    expect(observeUpdateProgress(attempt, completed(10_000_000)).terminal).toBe(
      true
    )
    expect(updateAttemptNotice(attempt, attempt.pollUntil)).toBe(
      "resultUnknown"
    )
    saveUpdateAttempt(saved, attempt)
    // Stop monitoring only clears local state, allowing a separate fresh GET.
    saveUpdateAttempt(saved, null)
    expect(loadUpdateAttempt(saved)).toBeNull()
    expect(attempt.accepted).toBe(false)
  })

  test("invalid status bodies are not an empty successful response", () => {
    for (const body of [
      null,
      {},
      "<html>",
      { running: false },
      { running: false, log: "", success: "yes" },
    ]) {
      expect(parseUpdateProgress(body)).toBeNull()
    }
    expect(
      parseUpdateProgress({ ...running(101), percent: 180 })?.percent
    ).toBe(100)
    expect(updateHttpStatus(new TypeError("Failed to fetch"))).toBeNull()
  })

  test("progress preserves current rollback availability including a failed update", () => {
    const progress = parseUpdateProgress({
      running: false,
      log: "failed",
      phase: "failed",
      success: false,
      updated_at: 102,
      package_rescue_ready: true,
      package_rollback_available: true,
      package_rollback_state: "ready",
    })!
    expect(progress.package_rescue_ready).toBe(true)
    expect(progress.package_rollback_available).toBe(true)
    expect(progress.package_rollback_state).toBe("ready")
    expect(
      observeUpdateProgress(newUpdateAttempt("update", "", 100), progress)
        .terminal
    ).toBe(true)
    const disabled = parseUpdateProgress({
      ...progress,
      package_rollback_available: false,
    })!
    expect(disabled.package_rollback_available).toBe(false)
    const malformed = parseUpdateProgress({
      ...progress,
      package_rescue_ready: "yes",
      package_rollback_available: "true",
      package_rollback_state: { secret: "not a state" },
    })!
    expect(malformed.package_rescue_ready).toBeUndefined()
    expect(malformed.package_rollback_available).toBeUndefined()
    expect(malformed.package_rollback_state).toBeUndefined()
  })
})
