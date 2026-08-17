local auto_path = assert(arg[1], "zapret-auto.lua path is required")
local retransmission_path =
    assert(arg[2], "is_retransmission fixture path is required")

-- Deterministic nfqws primitives around the exact upstream Lua under test.
-- Test sequence numbers are small positive integers, so ordinary comparison
-- is equivalent to zapret-lib's wrap-aware seq_ge for this bounded fixture.
b_debug = false
VERDICT_PASS = 0
TH_RST = 0x04

function DLOG(_)
end

function DLOG_ERR(message)
    error(message)
end

function seq_ge(left, right)
    return left >= right
end

function bitand(_, _)
    return 0
end

function pos_get(desync, kind)
    assert(kind == "s", "this TCP-only harness requested an unexpected position")
    return assert(desync.test_sequence, "test sequence is missing")
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

local fake_now = 1000
os.time = function()
    return fake_now
end

assert(loadfile(retransmission_path), "retransmission fixture has a syntax error")()
assert(loadfile(auto_path), "zapret-auto.lua has a syntax error")()

local pool = "ppe_tcp"
local host = "blocked.example"

local function reset_state()
    autostate = {}
    fake_now = 1000
end

local function new_track()
    return {
        hostname = host,
        hostname_is_ip = false,
        lua_state = {},
        pos = {
            direct = {
                tcp = {
                    uppos_prev = 99,
                    pos = 100,
                },
            },
        },
    }
end

local function make_plan()
    return {
        {arg = {strategy = "1"}},
        {arg = {strategy = "2"}},
        {arg = {strategy = "3"}},
    }
end

local function run_event(track, options)
    local outgoing = options.kind ~= "success"
    track.pos.direct.tcp.uppos_prev =
        options.kind == "original" and 99 or 100
    track.pos.direct.tcp.pos = 100

    local desync = {
        arg = {
            key = pool,
            fails = tostring(options.fails),
            time = "300",
            retrans = tostring(options.retrans),
            maxseq = "32768",
            inseq = "4096",
        },
        dis = {
            tcp = {th_flags = 0},
            payload = outgoing and "clienthello" or "serverhello",
        },
        func_instance = "circular-v103-test",
        outgoing = outgoing,
        plan = make_plan(),
        test_sequence = outgoing and 100 or 5000,
        track = track,
    }

    circular(nil, desync)
    return desync.test_selected_strategy
end

local function host_record()
    return assert(
        autostate[pool] and autostate[pool][host],
        "circular did not create its host record")
end

local function assert_equal(actual, expected, label)
    assert(
        actual == expected,
        string.format(
            "%s: expected %s, got %s",
            label,
            tostring(expected),
            tostring(actual)))
end

local function latch_failure(track, retrans_threshold, fails_threshold)
    assert_equal(
        run_event(track, {
            kind = "original",
            retrans = retrans_threshold,
            fails = fails_threshold,
        }),
        1,
        "the original ClientHello must remain on slot 1")
    for _ = 1, retrans_threshold do
        run_event(track, {
            kind = "retransmission",
            retrans = retrans_threshold,
            fails = fails_threshold,
        })
    end
end

-- 1. Identical-sequence retransmits are not deduplicated in v1.0.3's
-- standard detector. Each observed retransmit advances the connection count.
reset_state()
local identical_track = new_track()
run_event(identical_track, {kind = "original", retrans = 2, fails = 2})
run_event(identical_track, {
    kind = "retransmission",
    retrans = 2,
    fails = 2,
})
assert_equal(
    identical_track.lua_state.automate.retrans,
    1,
    "first identical retransmit")
run_event(identical_track, {
    kind = "retransmission",
    retrans = 2,
    fails = 2,
})
assert_equal(
    identical_track.lua_state.automate.retrans,
    2,
    "second identical retransmit")
assert_equal(host_record().failure_counter, 1, "latched host failure")
assert_equal(host_record().nstrategy, 1, "fails=2 holds slot after one session")

-- 2. Once a connection latches failure, crec.nocheck suppresses a late
-- success on that same connection. A success on a later connection does reset
-- the pending per-host failure.
run_event(identical_track, {kind = "success", retrans = 2, fails = 2})
assert_equal(
    host_record().failure_counter,
    1,
    "same-connection late success is ignored")
local later_success_track = new_track()
run_event(later_success_track, {kind = "success", retrans = 2, fails = 2})
assert_equal(
    host_record().failure_counter,
    nil,
    "later-connection success clears pending failure")
assert_equal(host_record().nstrategy, 1, "success does not rotate")

-- 3. Two transient sessions that each latch before their late success rotate
-- at fails=2. This is the false-positive risk behind the conservative
-- production threshold and the ban on blind retrans=1.
reset_state()
local transient_one = new_track()
latch_failure(transient_one, 2, 2)
run_event(transient_one, {kind = "success", retrans = 2, fails = 2})
assert_equal(host_record().failure_counter, 1, "first transient session")
local transient_two = new_track()
latch_failure(transient_two, 2, 2)
assert_equal(host_record().nstrategy, 2, "second transient session rotates")
run_event(transient_two, {kind = "success", retrans = 2, fails = 2})
assert_equal(
    host_record().nstrategy,
    2,
    "late success cannot undo an already completed rotation")

-- 4. A genuine silent drop has no success packet. For retrans thresholds
-- 1/2/3, rotation with fails=1 happens on exactly the Nth observed identical
-- retransmission, never on the original ClientHello or before the threshold.
for retrans_threshold = 1, 3 do
    reset_state()
    local silent_track = new_track()
    assert_equal(
        run_event(silent_track, {
            kind = "original",
            retrans = retrans_threshold,
            fails = 1,
        }),
        1,
        "silent drop original packet")
    for retransmit = 1, retrans_threshold do
        local selected = run_event(silent_track, {
            kind = "retransmission",
            retrans = retrans_threshold,
            fails = 1,
        })
        assert_equal(
            selected,
            retransmit == retrans_threshold and 2 or 1,
            string.format(
                "silent drop retrans=%d event=%d",
                retrans_threshold,
                retransmit))
    end
end

print("zapret2 v1.0.3 circular semantic test passed")
