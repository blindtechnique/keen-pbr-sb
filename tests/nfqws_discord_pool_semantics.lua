local fixture = assert(arg[1], "pinned fixture directory is required")
local profiles = assert(arg[2], "packaged profiles directory is required")

-- Run pinned upstream circular/detectors; model only nfqws packet metadata,
-- per-instance range/payload gates and packet I/O. This is NOT a voice test.
b_debug, VERDICT_PASS, TH_RST = false, 0, 4
function DLOG(_) end
function DLOG_ERR(message) error(message) end
function ntop(address) return address end
function seq_ge(a, b) return a >= b end
function bitand(a, b) return (a == b) and b or 0 end
function orchestrate(_, _) end
function plan_instance_pop(desync) return table.remove(desync.plan, 1) end
function rawsend_dissect() error("Discord experiment must not send TCP resets") end
function pos_get(desync, kind, reverse)
    if kind == "s" then return desync.sequence end
    assert(kind == "n")
    if reverse == nil then reverse = not desync.outgoing end
    return reverse and desync.track.incoming or desync.track.outgoing
end

local function equal(actual, expected, message)
    assert(actual == expected, message .. ": expected " .. tostring(expected)
        .. ", got " .. tostring(actual))
end
local function contains(csv, value)
    for item in csv:gmatch("[^,]+") do if item == value then return true end end
    return false
end
local function in_range(range, desync)
    if range == "a" then return true end
    if range == "x" then return false end
    local comparison, kind, maximum = range:match("^([<%-])([ns])(%d+)$")
    assert(comparison, "unmodelled range " .. range)
    local position = pos_get(desync, kind)
    if comparison == "<" then return position < tonumber(maximum) end
    return position <= tonumber(maximum)
end
local function accepts(instance, desync)
    return in_range(desync.outgoing and instance.out_range or instance.in_range, desync)
        and (instance.payload == "all" or contains(instance.payload, desync.l7payload))
end
function plan_instance_execute(desync, verdict, instance)
    if accepts(instance, desync) then
        desync.executed[#desync.executed + 1] = instance.body
    end
    return verdict
end

local now = 2000000000
os.time = function() return now end
dofile(fixture .. "/zapret-lib-is-retransmission.lua")
dofile(fixture .. "/zapret-lib-host-ip.lua")
dofile(fixture .. "/zapret-auto.lua")
local saved_io, saved_error = io, DLOG_ERR
io, DLOG_ERR = nil, function(_) end
dofile(assert(arg[3], "production companion required"))
io, DLOG_ERR = saved_io, saved_error

local input = assert(io.open(profiles .. "/03 max/nfqws2.conf", "rb"))
local config = assert(input:read("*a"))
assert(input:close())
local custom = assert(config:match('NFQWS_ARGS_CUSTOM="(.-)"'))
local keys = {"discord_tcp_exp", "discord_media_tcp_exp", "discord_udp_exp"}
local pools = {}
for _, key in ipairs(keys) do
    local body = assert(custom:match("%-%-new=" .. key .. "%s+(.-)%-%-new="))
    local p = {key = key, instances = {}}
    local payload, incoming, outgoing = "all", "x", "a"
    for token in body:gmatch("%S+") do
        local name, value = token:match("^%-%-([%w%-]+)=(.*)$")
        if name == "payload" then payload = value
        elseif name == "in-range" then incoming = value
        elseif name == "out-range" then outgoing = value
        elseif name == "filter-tcp" then p.tcp = true
        elseif name == "lua-desync" then
            local instance = {body = value, arg = {}, payload = payload,
                in_range = incoming, out_range = outgoing}
            for name, val in value:gmatch(":([%w_]+)=([^:]+)") do instance.arg[name] = val end
            p.instances[#p.instances + 1] = instance
        end
    end
    equal(p.instances[1].arg.key, key, "independent key")
    equal(p.instances[1].arg.hostkey, "host_ip", "independent endpoint")
    pools[#pools + 1] = p
end

local function connection(ip)
    return {lua_state = {}, incoming = 0, outgoing = 0,
        target = (ip or ""):find(":", 1, true) and {ip6 = ip} or {ip = ip or "198.51.100.10"},
        pos = {direct = {tcp = {}}, reverse = {tcp = {winsize = 1024}}}}
end
local function event(p, track, outgoing, position, payload, retransmit, rst)
    track[outgoing and "outgoing" or "incoming"] = position
    track.pos.direct.tcp = {pos = 1, uppos_prev = retransmit and 1 or 0}
    local d = {arg = p.instances[1].arg, target = track.target, track = track,
        outgoing = outgoing, sequence = position, l7payload = payload,
        dis = {payload = "fixture", tcp = p.tcp and {th_flags = rst and TH_RST or 0},
            udp = not p.tcp and {} or nil},
        plan = {}, executed = {}, func_instance = p.key}
    for i = 2, #p.instances do d.plan[#d.plan + 1] = p.instances[i] end
    local observed = accepts(p.instances[1], d)
    if observed then circular(nil, d)
    else
        -- When circular does not match, C continues the ordinary plan. An
        -- action escaping the observer would execute BOTH candidate slots.
        for _, instance in ipairs(d.plan) do plan_instance_execute(d, VERDICT_PASS, instance) end
    end
    return d.executed, observed
end
local function record(p, track)
    return assert(autostate[p.key][track.target.ip or track.target.ip6])
end
local function fail(p, track)
    if p.tcp then
        event(p, track, true, 1, "tls_client_hello")
        event(p, track, true, 1, "tls_client_hello", true)
        event(p, track, true, 1, "tls_client_hello", true)
    else
        for n = 1, 4 do
            local actions, observed = event(p, track, true, n, "discord_ip_discovery")
            assert(observed, "all four outgoing packets must reach the detector")
            equal(#actions, n == 1 and 1 or 0, "only initial UDP packet is altered")
        end
    end
    return record(p, track)
end
local function success(p, track)
    local count = p.tcp and 1 or 2
    for n = 1, count do
        local actions, observed = event(p, track, false, p.tcp and 8193 or n, "unknown")
        assert(observed, "reply must reach the success detector")
        equal(#actions, 0, "replies are observation-only")
    end
end

local scenarios = 0
for _, p in ipairs(pools) do
    autostate = {}
    local a, b = connection(), connection()
    local first = fail(p, a)
    equal(first.failure_counter, 1, "one failure must not skip a candidate")
    equal(first.nstrategy, 1, "first candidate retained")
    local second = fail(p, b)
    equal(second.nstrategy, 2, "second failed session selects candidate 2")
    equal(first, second, "same target compared with both candidates")
    local retry = connection()
    local actions = event(p, retry, true, 1, p.tcp and "tls_client_hello" or "discord_ip_discovery")
    equal(#actions, p.tcp and 3 or 1, "only the selected candidate's actions execute")
    for _, action in ipairs(actions) do assert(action:find(":strategy=2", 1, true)) end
    fail(p, connection())
    fail(p, connection())
    equal(first.nstrategy, 1, "full circular wrap back to candidate 1")
    scenarios = scenarios + 1

    autostate = {}
    local failed, working = connection(), connection("198.51.100.20")
    local pending = fail(p, failed)
    success(p, working)
    equal(pending.failure_counter, 1, "another endpoint cannot hide a failure")
    local recovered = connection()
    success(p, recovered)
    equal(pending.failure_counter, nil, "a response from this endpoint clears its failure")
    scenarios = scenarios + 1

    -- Healthy connections stay healthy on later retransmissions/datagrams.
    fail(p, recovered)
    equal(pending.failure_counter, nil, "confirmed traffic is not a new failure")
    scenarios = scenarios + 1

    autostate = {}
    local v6 = connection("2001:db8::10")
    local pending6 = fail(p, v6)
    success(p, connection("2001:db8::20"))
    equal(pending6.failure_counter, 1, "IPv6 endpoint isolation")
    scenarios = scenarios + 1

    autostate = {}
    local old = fail(p, connection())
    now = now + 301
    fail(p, connection())
    equal(old.nstrategy, 1, "expired failures must not advance a candidate")
    scenarios = scenarios + 1

    local unrelated = event(p, connection(), true, 1, p.tcp and "http_req" or "rtp")
    equal(#unrelated, 0, "unrelated payload / actual media receives no fake")
    local late, observed = event(p, connection(), true, p.tcp and 66997 or 5,
        p.tcp and "tls_client_hello" or "discord_ip_discovery")
    equal(observed, false, "bounded observer window")
    equal(#late, 0, "no candidate may escape the observer range")
    local reply = event(p, connection(), false, p.tcp and 9653 or 3, "unknown")
    equal(#reply, 0, "late incoming traffic must not get fake packets")
    scenarios = scenarios + 1
end

-- Same remote IP, independent TCP, alternate-port TLS, UDP and old key.
autostate = {discord_udp = {["198.51.100.10"] = {nstrategy = 4}}}
for _, p in ipairs(pools) do fail(p, connection()) end
fail(pools[1], connection())
equal(record(pools[1], connection()).nstrategy, 2, "TCP rotation")
equal(record(pools[2], connection()).nstrategy, 1, "alternate TCP is independent")
equal(record(pools[3], connection()).nstrategy, 1, "UDP is independent from TCP")
equal(autostate.discord_udp["198.51.100.10"].nstrategy, 4, "old UDP state untouched")
scenarios = scenarios + 1
print("nfqws Discord semantics passed: " .. scenarios .. " scenarios; not a live call test")
