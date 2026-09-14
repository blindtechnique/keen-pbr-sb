local fixture = assert(arg[1], "upstream fixture directory is required")
local profiles = assert(arg[2], "generated profiles directory is required")

-- The orchestrator, detectors, retransmission predicate and endpoint key are
-- pinned upstream functions. Packet I/O and nfqws primitives are deterministic
-- stand-ins: this proves selection/retry semantics, not a live TCP reset.
b_debug = false
VERDICT_PASS = 0
TH_RST = 4

function DLOG(_) end
function DLOG_ERR(message) error(message) end
function ntop(address) return address end
function seq_ge(left, right) return left >= right end
function bitand(left, right)
    local result, place = 0, 1
    while left > 0 and right > 0 do
        if left % 2 == 1 and right % 2 == 1 then result = result + place end
        left, right, place = math.floor(left / 2), math.floor(right / 2), place * 2
    end
    return result
end
function deepcopy(value)
    if type(value) ~= "table" then return value end
    local result = {}
    for key, item in pairs(value) do result[key] = deepcopy(item) end
    return result
end
function dissect_nld(host, count)
    local labels = {}
    for label in string.gmatch(host, "[^.]+") do labels[#labels + 1] = label end
    if #labels < count then return nil end
    return table.concat(labels, ".", #labels - count + 1)
end
function pos_get(desync, kind)
    assert(kind == "s", "TCP-only test")
    return desync.test_sequence
end
function orchestrate(_, _) end
function plan_instance_pop(desync) return table.remove(desync.plan, 1) end
function plan_instance_execute(desync, verdict, instance)
    desync.test_selected = tonumber(instance.arg.strategy)
    return verdict
end
function dis_reverse(dis)
    dis.test_source, dis.test_destination = dis.test_destination, dis.test_source
    dis.tcp.th_sport, dis.tcp.th_dport = dis.tcp.th_dport, dis.tcp.th_sport
end

local resets = {}
function rawsend_dissect(dis, options)
    assert(dis.tcp.th_flags == TH_RST)
    assert(dis.tcp.th_sport == 443 and dis.tcp.th_dport == dis.test_client_port)
    assert(dis.test_source == dis.test_server and dis.test_destination == dis.test_client)
    assert(dis.payload == nil and dis.tcp.options == nil)
    assert(options.ifout == "test-lan")
    resets[#resets + 1] = dis.test_connection
end

local fake_now = 2000000000
os.time = function() return fake_now end
dofile(fixture .. "/zapret-lib-is-retransmission.lua")
dofile(fixture .. "/zapret-lib-host-ip.lua")
dofile(fixture .. "/zapret-auto.lua")
local saved_io, saved_error = io, DLOG_ERR
io, DLOG_ERR = nil, function(_) end
dofile(assert(arg[3], "production companion required"))
io, DLOG_ERR = saved_io, saved_error

local function equal(actual, expected, label)
    assert(actual == expected, label .. ": expected " .. tostring(expected)
        .. ", got " .. tostring(actual))
end
local function read_profile(name)
    local handle = assert(io.open(profiles .. "/" .. name .. "/nfqws2.conf", "rb"))
    local text = assert(handle:read("*a"))
    assert(handle:close())
    local custom = assert(text:match('NFQWS_ARGS_CUSTOM="(.-)"'))
    local block = assert(custom:match("^(.-)%-%-new="))
    local token = assert(block:match("%-%-lua%-desync=circular:([^%s]+)"))
    local options = {}
    for item in token:gmatch("[^:]+") do
        local key, value = item:match("^([^=]+)=(.*)$")
        assert(key and value, "invalid circular argument")
        options[key] = value
    end
    equal(options.key, "gv_tcp", "first custom pool")
    local plan = {}
    for slot in block:gmatch(":strategy=(%d+)") do
        plan[#plan + 1] = {arg = {strategy = slot}}
    end
    return options, plan
end

local serial = 0
local function connection(server, hostname)
    serial = serial + 1
    return {
        hostname = hostname or "rr1.example.googlevideo.com",
        hostname_is_ip = false,
        lua_state = {},
        target = server:find(":", 1, true) and {ip6 = server} or {ip = server},
        server = server,
        client = "192.0.2.10",
        port = 40000 + serial,
        id = serial,
        pos = {direct = {tcp = {}}, reverse = {tcp = {winsize = 1024}}},
    }
end
local function event(track, kind, options, plan)
    local outgoing = kind ~= "success" and kind ~= "server_ack" and kind ~= "server_rst"
    track.pos.direct.tcp.pos = 1
    track.pos.direct.tcp.uppos_prev = kind == "original" and 0 or 1
    local desync = {
        arg = deepcopy(options),
        target = track.target,
        track = track,
        outgoing = outgoing,
        ifin = outgoing and "test-lan" or "test-wan",
        func_instance = "video-test",
        plan = deepcopy(plan),
        test_sequence = kind == "success" and 8193 or 1,
        dis = {
            tcp = {
                th_flags = kind == "server_rst" and TH_RST or 0,
                th_sport = outgoing and track.port or 443,
                th_dport = outgoing and 443 or track.port,
                options = {},
            },
            payload = kind == "server_ack" and "" or "tls-payload",
            test_source = outgoing and track.client or track.server,
            test_destination = outgoing and track.server or track.client,
            test_server = track.server,
            test_client = track.client,
            test_client_port = track.port,
            test_connection = track.id,
        },
    }
    circular(nil, desync)
    local generator = options.hostkey and _G[options.hostkey] or standard_hostkey
    return desync.test_selected, assert(autostate.gv_tcp[generator(desync)])
end
local function fail(track, options, plan)
    event(track, "original", options, plan)
    event(track, "retransmission", options, plan)
    return event(track, "retransmission", options, plan)
end

local cases = 0
for _, profile in ipairs({"02 balanced", "03 max"}) do
    local options, plan = read_profile(profile)
    autostate, resets = {}, {}
    local broken = connection("198.51.100.10")
    local selected, broken_record = fail(broken, options, plan)
    equal(selected, 1, "one failed session retains conservative fails=2")
    equal(broken_record.failure_counter, 1, "first pending failure")
    local good = connection("198.51.100.20") -- same SNI, different CDN endpoint
    local _, good_record = event(good, "original", options, plan)
    event(good, "success", options, plan)
    equal(broken_record.failure_counter, 1, "another CDN must not erase this failure")
    assert(good_record ~= broken_record, "CDN endpoints share one record")
    cases = cases + 1

    equal(#resets, 1, "first failed session is released")
    equal(resets[1], broken.id, "only the failed connection is reset")
    event(broken, "retransmission", options, plan)
    equal(#resets, 1, "retransmissions after a detected failure cannot reset twice")
    local retry = connection("198.51.100.10")
    selected = fail(retry, options, plan)
    equal(selected, 2, "second failed session advances to the next strategy")
    equal(#resets, 2, "second failed attempt is also released")
    equal(resets[2], retry.id, "retry reset stays connection-local")
    equal(good_record.nstrategy, 1, "rotation cannot change another CDN")
    local fresh = connection("198.51.100.10")
    equal(event(fresh, "original", options, plan), 2, "new attempt uses rotated slot")
    cases = cases + 1

    -- Endpoint isolation must retain a true circle through the entire shipped
    -- pool, including the wrap to slot 1, without advancing the working CDN.
    local slots = broken_record.ctstrategy
    equal(slots, 5, "complete shipped video pool")
    for slot = 2, slots do
        equal(fail(connection("198.51.100.10"), options, plan), slot,
            "one failed session must not skip a slot")
        equal(fail(connection("198.51.100.10"), options, plan), slot % slots + 1,
            "two failed sessions advance exactly one slot")
        equal(good_record.nstrategy, 1, "full cycle cannot advance the other CDN")
    end
    cases = cases + 1

    -- One lost packet is not sufficient to interrupt a healthy player.
    autostate, resets = {}, {}
    local transient = connection("198.51.100.30")
    event(transient, "original", options, plan)
    event(transient, "server_ack", options, plan)
    event(transient, "retransmission", options, plan)
    equal(#resets, 0, "no reset before the second retransmission")
    event(transient, "success", options, plan)
    event(transient, "retransmission", options, plan)
    local _, transient_record = event(transient, "retransmission", options, plan)
    equal(#resets, 0, "proven healthy connection is never forcibly reconnected")
    equal(transient_record.nstrategy, 1, "a transient loss must not rotate")
    cases = cases + 1

    -- Aliases reaching the same endpoint share learning, not the entire suffix.
    autostate, resets = {}, {}
    local alias_a = connection("198.51.100.40", "rr1.cdn.googlevideo.com")
    local alias_b = connection("198.51.100.40", "rr2.other.googlevideo.com")
    local _, alias_record = event(alias_a, "original", options, plan)
    local _, same_record = event(alias_b, "server_ack", options, plan)
    equal(same_record, alias_record, "endpoint key stays stable across SNI/direction")
    cases = cases + 1

    autostate, resets = {}, {}
    local ipv6_a = connection("2001:db8::10")
    local ipv6_b = connection("2001:db8::20")
    local _, ipv6_failure = fail(ipv6_a, options, plan)
    event(ipv6_b, "original", options, plan)
    event(ipv6_b, "success", options, plan)
    equal(ipv6_failure.failure_counter, 1, "IPv6 endpoints have independent failures")
    equal(#resets, 1, "IPv6 reset remains local to the failed attempt")
    cases = cases + 1

    autostate, resets = {}, {}
    local expired = connection("198.51.100.50")
    fail(expired, options, plan)
    fake_now = fake_now + 301
    local later = connection("198.51.100.50")
    selected = fail(later, options, plan)
    equal(selected, 1, "old failures expire rather than forcing a later rotation")
    cases = cases + 1

    autostate, resets = {}, {}
    local reset_a = connection("198.51.100.60")
    event(reset_a, "original", options, plan)
    local _, reset_record = event(reset_a, "server_rst", options, plan)
    equal(reset_record.failure_counter, 1, "server RST retains stock failure accounting")
    equal(#resets, 0, "do not send an extra reset in response to a server reset")
    cases = cases + 1
end
print("nfqws video TCP semantics passed: " .. cases .. " scenarios")
