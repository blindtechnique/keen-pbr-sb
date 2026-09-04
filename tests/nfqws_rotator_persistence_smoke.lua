local companion = assert(arg[1], "companion path is required")
local auto_path = assert(arg[2], "zapret-auto.lua path is required")
local writable = assert(os.getenv("WRITABLE"), "WRITABLE is required")
local persistent_prefix = assert(
    os.getenv("KEEN_PBR_NFQWS_ROTATOR_LEARNED_PREFIX"),
    "learned-state prefix is required")

local REVISION = "0123456789abcdef"
local OTHER_REVISION = "fedcba9876543210"
local DAY = 24 * 60 * 60
local SYNCED_NOW = 2000000000
local fake_now = 100
local real_open = io.open

local function assert_equal(actual, expected, label)
    assert(
        actual == expected,
        string.format(
            "%s: expected %s, got %s",
            label,
            tostring(expected),
            tostring(actual)))
end

local function hex_encode(value)
    return (string.gsub(value, ".", function(character)
        return string.format("%02x", string.byte(character))
    end))
end

local function write_file(path, content)
    local handle = assert(real_open(path, "wb"))
    assert(handle:write(content))
    assert(handle:close())
end

local function read_file(path)
    local handle = assert(real_open(path, "rb"))
    local content = assert(handle:read("*a"))
    assert(handle:close())
    return content
end

local written_at = SYNCED_NOW - 21601
local confirmed_at = written_at - 1
local seed_rows = {
    {"yt_tcp", REVISION, "youtube.com", 2, 3, confirmed_at},
    {"yt_tcp", REVISION, "googleapis.com", 2, 3, confirmed_at},
    {"yt_tcp", REVISION, "mismatch.example", 3, 3, confirmed_at},
    {"yt_tcp", REVISION, "waiting.example", 2, 3, confirmed_at},
    {
        "yt_tcp",
        REVISION,
        "expired.example",
        3,
        3,
        SYNCED_NOW - (30 * DAY) - 1,
    },
}
local seed = {
    string.format("KPRS1\t7\t%d\t%d", written_at, #seed_rows),
}
for _, row in ipairs(seed_rows) do
    seed[#seed + 1] = string.format(
        "S\t%s\t%s\t%s\t%d\t%d\t%d",
        hex_encode(row[1]),
        row[2],
        hex_encode(row[3]),
        row[4],
        row[5],
        row[6])
end
seed[#seed + 1] = string.format("END\t7\t%d", #seed_rows)
write_file(persistent_prefix .. ".0", "KPRS1\t99\tbroken\n")
write_file(persistent_prefix .. ".1", table.concat(seed, "\n") .. "\n")

local timer_callback = nil
local timer_deleted = false
local aggregate_writes = 0
local persistent_writes = 0
local fail_persistent_write = false
local logged_errors = {}

io.open = function(path, mode)
    if path == "/proc/self/stat" then
        return {
            read = function(_, format)
                assert(format == "*l")
                return "111 (nfqws2) S 4 5 6 7 8 9 10 11 12 13 14 15 " ..
                    "16 17 18 19 20 21 222 23 24"
            end,
            close = function()
                return true
            end,
        }
    end
    if mode == "w"
        and string.find(
            path, writable .. "/rotator-state.", 1, true) == 1 then
        aggregate_writes = aggregate_writes + 1
    end
    if mode == "w"
        and (path == persistent_prefix .. ".0"
            or path == persistent_prefix .. ".1") then
        if fail_persistent_write then
            return nil, "injected learned-state failure"
        end
        persistent_writes = persistent_writes + 1
    end
    return real_open(path, mode)
end

os.time = function()
    return fake_now
end

b_debug = false
VERDICT_PASS = 0
TH_RST = 0x04

function DLOG(_)
end

function DLOG_ERR(message)
    logged_errors[#logged_errors + 1] = tostring(message)
end

function timer_set(name, callback, period, oneshot, data)
    assert_equal(name, "keen_pbr_rotator_telemetry", "timer name")
    assert_equal(period, 10000, "timer period")
    assert_equal(oneshot, false, "timer mode")
    assert(data == nil)
    timer_callback = type(callback) == "string"
        and assert(_G[callback], "timer callback is unavailable")
        or assert(callback)
end

function timer_del(name)
    assert_equal(name, "keen_pbr_rotator_telemetry", "deleted timer")
    timer_deleted = true
end

function seq_ge(left, right)
    return left >= right
end

function bitand(left, right)
    local result = 0
    local place = 1
    while left > 0 and right > 0 do
        if left % 2 == 1 and right % 2 == 1 then
            result = result + place
        end
        left = math.floor(left / 2)
        right = math.floor(right / 2)
        place = place * 2
    end
    return result
end

function pos_get(desync, kind)
    assert_equal(kind, "s", "TCP position kind")
    return assert(desync.test_sequence, "test sequence is missing")
end

function dissect_nld(host, count)
    local labels = {}
    for label in string.gmatch(host, "[^.]+") do
        labels[#labels + 1] = label
    end
    if #labels < count then
        return nil
    end
    return table.concat(labels, ".", #labels - count + 1)
end

function orchestrate(_, _)
end

function plan_instance_pop(desync)
    return table.remove(desync.plan, 1)
end

function plan_instance_execute(desync, verdict, instance)
    desync.test_selected_strategy = tonumber(instance.arg.strategy)
    return verdict
end

assert(loadfile(auto_path), "zapret-auto.lua has a syntax error")()
local stock_host_record = automate_host_record
local stock_success_detector = standard_success_detector

assert(loadfile(companion), "companion has a syntax error")
dofile(companion)
assert(type(timer_callback) == "function", "periodic timer was not installed")
assert(automate_host_record ~= stock_host_record,
    "stock host-record hook was not wrapped")
assert(standard_success_detector ~= stock_success_detector,
    "stock success detector was not wrapped")
assert_equal(aggregate_writes, 1, "initial aggregate publication")
assert_equal(persistent_writes, 0, "startup must not rewrite learned state")

local function make_plan(count)
    local plan = {}
    for slot = 1, count do
        plan[#plan + 1] = {arg = {strategy = tostring(slot)}}
    end
    return plan
end

local function run_event(hostname, revision, slot_count, kind, options)
    options = options or {}
    local outgoing = kind ~= "success" and kind ~= "failure"
    local desync = {
        arg = {
            key = "yt_tcp",
            kpbr_rev = revision,
            nld = "2",
            fails = tostring(options.fails or 2),
            time = "300",
            retrans = "2",
            maxseq = "32768",
            inseq = tostring(options.inseq or 4096),
        },
        dis = {
            tcp = {th_flags = kind == "failure" and TH_RST or 0},
            -- An empty first payload keeps this smoke away from the unrelated
            -- retransmission detector. Incoming s5000 is a stock success.
            payload = outgoing and "" or "serverhello",
        },
        func_instance = "persistence-smoke",
        outgoing = outgoing,
        plan = make_plan(slot_count),
        test_sequence = options.sequence
            or (outgoing and 100 or (kind == "failure" and 1 or 5000)),
        track = {
            hostname = hostname,
            hostname_is_ip = false,
            lua_state = {},
        },
    }
    assert(desync.arg.success_detector == nil,
        "eligible pools must use the stock detector without a reporter arg")
    circular(nil, desync)
    local host_key = assert(dissect_nld(hostname, 2))
    local host_record = assert(autostate.yt_tcp[host_key])
    return desync.test_selected_strategy, host_record
end

-- A Keenetic cold boot can start nfqws2 before NTP. The structurally valid
-- 2026 snapshot is an advisory seed immediately, but a new success and durable
-- writes remain blocked until the clock catches up.
local selected = run_event("m.youtube.com", REVISION, 3, "original")
assert_equal(selected, 2, "first pre-NTP request restores the learned slot")
selected = run_event("preclock.example", REVISION, 3, "success")
assert_equal(selected, 1, "pre-NTP stock strategy for an unknown host")
timer_callback("keen_pbr_rotator_telemetry", nil)
assert_equal(persistent_writes, 0, "pre-NTP durable write")

-- A superficially plausible wall clock is still not ready while it is behind
-- the selected durable snapshot. The timer must retain that snapshot.
fake_now = written_at - 3600
timer_callback("keen_pbr_rotator_telemetry", nil)
assert_equal(persistent_writes, 0, "behind-snapshot durable write")
selected = run_event(
    "sub.waiting.example", REVISION, 3, "original")
assert_equal(selected, 2, "future snapshot survived an intermediate clock")

fake_now = SYNCED_NOW
timer_callback("keen_pbr_rotator_telemetry", nil)
assert_equal(persistent_writes, 0, "NTP retry without a proven success")

local restored
restored = autostate.yt_tcp["youtube.com"]
assert(restored, "pre-NTP youtube record disappeared after NTP")
assert_equal(restored.nstrategy, 2, "restored strategy")
assert_equal(restored.ctstrategy, 3, "stock strategy count")
assert(restored.failure_counter == nil,
    "restore must not invent a failure counter")

selected = run_event(
    "youtubei.googleapis.com", REVISION, 2, "original")
assert_equal(selected, 1, "strategy-count mismatch must fail open")
selected = run_event(
    "sub.mismatch.example", OTHER_REVISION, 3, "original")
assert_equal(selected, 1, "revision mismatch must fail open")
selected = run_event(
    "sub.expired.example", REVISION, 3, "original")
assert_equal(selected, 1, "expired selection must fail open")

-- The live nfqws2-keenetic firewall queues only the first 15 reply packets.
-- A failure rotates the slot but is not durable by itself; a new connection
-- must prove more than 8 KiB of incoming application data before that exact
-- rotated slot may be persisted.
selected = run_event(
    "visibility.example", REVISION, 3, "failure",
    {fails = 1, inseq = 8192, sequence = 1})
assert_equal(selected, 2, "bounded failure rotates to slot 2")
selected = run_event(
    "visibility.example", REVISION, 3, "success",
    {fails = 1, inseq = 8192, sequence = 8193})
assert_equal(selected, 2, "new bounded success keeps rotated slot 2")

selected = run_event("fresh.example", REVISION, 3, "success")
assert_equal(selected, 1, "new host starts on stock slot 1")

timer_callback("keen_pbr_rotator_telemetry", nil)
assert_equal(persistent_writes, 0, "first dirty debounce at zero seconds")
fake_now = fake_now + 119
timer_callback("keen_pbr_rotator_telemetry", nil)
assert_equal(persistent_writes, 0, "first dirty debounce at 119 seconds")
fake_now = fake_now + 1
timer_callback("keen_pbr_rotator_telemetry", nil)
assert_equal(persistent_writes, 1, "first learned-state publication")

local first_persisted = read_file(persistent_prefix .. ".0")
assert(string.match(first_persisted, "^KPRS1\t8\t%d+\t6\n"))
assert(string.find(
    first_persisted, hex_encode("fresh.example"), 1, true))
assert(string.find(
    first_persisted, hex_encode("visibility.example"), 1, true))
assert(not string.find(
    first_persisted, hex_encode("expired.example"), 1, true))
assert(not string.find(
    first_persisted, hex_encode("preclock.example"), 1, true))
assert(not string.find(first_persisted, "failure", 1, true),
    "failure counters leaked into durable state")

for index = 1, 70 do
    run_event(
        string.format("cap%03d.example", index),
        REVISION,
        3,
        "success")
end
fake_now = fake_now + 120
timer_callback("keen_pbr_rotator_telemetry", nil)
assert_equal(
    persistent_writes, 1, "six-hour hard write interval was bypassed")
fake_now = fake_now + (6 * 60 * 60) - 120
timer_callback("keen_pbr_rotator_telemetry", nil)
assert_equal(persistent_writes, 2, "bounded learned-state publication")
local capped = read_file(persistent_prefix .. ".1")
assert(string.match(capped, "^KPRS1\t9\t%d+\t64\n"))
assert(string.match(capped, "END\t9\t64\n$"))

run_event("cap001.example", REVISION, 3, "success")
timer_callback("keen_pbr_rotator_telemetry", nil)
assert_equal(
    persistent_writes, 2, "same-slot success refreshed before seven days")

local cap_confirmation = SYNCED_NOW + 120
fake_now = cap_confirmation + (7 * DAY)
run_event("cap001.example", REVISION, 3, "success")
fake_now = fake_now + 119
timer_callback("keen_pbr_rotator_telemetry", nil)
assert_equal(persistent_writes, 2, "refresh debounce at 119 seconds")
fake_now = fake_now + 1
timer_callback("keen_pbr_rotator_telemetry", nil)
assert_equal(persistent_writes, 3, "seven-day same-slot refresh")

run_event("iofail.example", REVISION, 3, "success")
fake_now = fake_now + (6 * 60 * 60) + 120
local aggregate_before_failure = aggregate_writes
fail_persistent_write = true
local survived, timer_error =
    pcall(timer_callback, "keen_pbr_rotator_telemetry", nil)
assert(survived, timer_error)
assert_equal(
    aggregate_writes,
    aggregate_before_failure + 1,
    "aggregate publication during learned-state failure")
assert_equal(persistent_writes, 3, "failed learned-state write accounting")
assert(not timer_deleted,
    "learned-state failure disabled aggregate telemetry timer")
assert(string.find(
    table.concat(logged_errors, "\n"),
    "injected learned-state failure",
    1,
    true))

local aggregate_after_failure = aggregate_writes
timer_callback("keen_pbr_rotator_telemetry", nil)
assert_equal(
    aggregate_writes,
    aggregate_after_failure + 1,
    "aggregate telemetry after persistence was disabled")
assert(not timer_deleted,
    "aggregate timer was removed after persistence failed open")

print("nfqws rotator learned-state Lua smoke passed")
