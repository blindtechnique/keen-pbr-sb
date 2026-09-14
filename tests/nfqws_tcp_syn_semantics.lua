local fixture = assert(arg[1], "upstream fixture directory required")
local companion = assert(arg[2], "companion required")
local profiles = assert(arg[3], "generated profiles required")

-- Real upstream circular/failure bookkeeping, mocked packet send. Native
-- packet capture is still required to prove that the profile matches SYN.
VERDICT_PASS, VERDICT_DROP = 0, 1
TH_SYN, TH_ACK, TH_RST = 2, 16, 4
b_debug = false
function DLOG(_) end
function DLOG_ERR(message) error(message) end
function bitand(a, b)
    local result, place = 0, 1
    while a > 0 and b > 0 do
        if a % 2 == 1 and b % 2 == 1 then result = result + place end
        a, b, place = math.floor(a / 2), math.floor(b / 2), place * 2
    end
    return result
end
function host_ip(desync) return desync.test_ip end
function pos_get(desync, _) return desync.test_seq or 0 end
function is_retransmission(desync) return desync.test_retrans or false end
function orchestrate(_, _) end
function plan_instance_pop(desync) return table.remove(desync.plan, 1) end
function deepcopy(value)
    if type(value) ~= "table" then return value end
    local result = {}
    for key, item in pairs(value) do result[key] = deepcopy(item) end
    return result
end

local sends, selected = 0, nil
local executed = {}
local function in_range(range, desync)
    if range == 'a' then return true end
    if range == 'x' then return false end
    local mode, maximum = range:match('^%-([ns])(%d+)$')
    assert(mode, 'unexpected range ' .. range)
    return (mode == 's' and desync.test_seq or desync.test_packet) <= tonumber(maximum)
end
local function accepts(instance, desync)
    if not in_range(desync.outgoing and instance.out_range or instance.in_range, desync) then return false end
    if instance.payload == 'all' then return true end
    for payload in instance.payload:gmatch('[^,]+') do
        if payload == desync.l7payload then return true end
    end
    return false
end
function syndata(_, _)
    sends = sends + 1
    return VERDICT_DROP
end
function plan_instance_execute(desync, verdict, instance)
    if not accepts(instance, desync) then return verdict end
    executed[#executed+1] = instance.name
    selected = tonumber(instance.arg.strategy)
    if instance.name == 'keen_pbr_syndata' then
        return keen_pbr_syndata(nil, desync)
    end
    return verdict
end
dofile(fixture .. "/zapret-auto.lua")
-- Disable I/O setup, not the production TCP helpers under test.
local saved_io = io
io = nil
local saved_error = DLOG_ERR
DLOG_ERR = function(_) end
dofile(companion)
io, DLOG_ERR = saved_io, saved_error

local function equal(actual, expected, label)
    assert(actual == expected, label .. ": expected " .. tostring(expected) .. ", got " .. tostring(actual))
end
local handle = assert(io.open(profiles .. "/03 max/nfqws2.conf", "rb"))
local config = assert(handle:read("*a"))
handle:close()
local tcp = assert(config:match('NFQWS_ARGS="(.-)"'))
local opts = {}
for key, value in tcp:match("%-%-lua%-desync=circular:([^%s]+)"):gmatch("([^:=]+)=([^:]+)") do
    opts[key] = value
end
local plan, observer = {}, nil
local payload, incoming, outgoing = 'all', 'x', 'a'
for token in tcp:gmatch('%S+') do
    local name, value = token:match('^%-%-([%w%-]+)=(.*)$')
    if name == 'payload' then payload = value
    elseif name == 'in-range' then incoming = value
    elseif name == 'out-range' then outgoing = value
    elseif name == 'lua-desync' then
        local item = {name = value:match('^[^:]+'), arg = {},
            payload = payload, in_range = incoming, out_range = outgoing}
        for k, v in value:gmatch(':([%w_]+)=([^:]+)') do item.arg[k] = v end
        if item.name == 'circular' then observer = item else plan[#plan+1] = item end
    end
end
equal(opts.hostkey, "keen_pbr_tcp_endpoint", "SYN/TLS endpoint identity")
equal(opts.failure_detector, "keen_pbr_syn_failure_detector", "shipped detector")

local function connection()
    return {lua_state = {}, packets = 0}
end
local function event(track, kind, ip, port)
    local syn = kind == "syn"
    local reply = kind == "reply" or kind == "rst" or kind == "success"
    track.packets = track.packets + 1
    local d = {
        track = track, arg = deepcopy(opts), plan = deepcopy(plan), outgoing = not reply,
        func_instance = "test-tcp", test_ip = ip or "198.51.100.10",
        test_seq = kind == "success" and 26001 or (syn and 0 or 1),
        test_packet = track.packets,
        l7payload = (syn or reply) and 'empty' or (kind == 'http' and 'http_req' or 'unknown'),
        test_retrans = kind == "retrans", test_syn_action = syn,
        dis = {tcp = {
            th_flags = syn and TH_SYN or (kind == "rst" and TH_RST or TH_ACK),
            th_sport = reply and (port or 443) or 41000,
            th_dport = reply and 41000 or (port or 443),
        }, payload = kind == "success" and "server-data" or ((syn or reply) and "" or "tls")},
    }
    selected, executed = nil, {}
    if accepts(observer, d) then circular(nil, d)
    else for _, item in ipairs(d.plan) do plan_instance_execute(d, VERDICT_PASS, item) end end
    local record = autostate and autostate.tcp_general and autostate.tcp_general[keen_pbr_tcp_endpoint(d)]
    return record and record.nstrategy or selected, d
end
local function seed(ip, port, slot)
    autostate = {tcp_general = {[(ip or "198.51.100.10") .. "|" .. tostring(port or 443)] = {nstrategy = slot or 12}}}
end

local cases = 0
seed()
sends = 0
local first = connection()
equal(event(first, "syn"), 12, "SYN selects slot 12")
equal(sends, 1, "first SYN calls the stock action")
event(first, "syn")
equal(sends, 1, "first retry is passed unmodified")
event(first, "syn")
local record = autostate.tcp_general["198.51.100.10|443"]
equal(record.failure_counter, 1, "two SYN retries count one failed connection")
event(first, "syn")
equal(record.failure_counter, 1, "same connection cannot count twice")
local second = connection()
event(second, "syn")
event(second, "syn")
equal(event(second, "syn"), 1, "two failed connections rotate to the first slot")
equal(sends, 2, "never resubmit fake SYN within one connection")
equal(event(connection(), "syn"), 1, "new connection uses non-SYN fallback")
equal(sends, 2, "fallback slot does not send SYN data")
cases = cases + 1

seed(nil, nil, 1)
local ordinary = connection()
event(ordinary, "syn"); event(ordinary, "syn"); event(ordinary, "syn")
equal(autostate.tcp_general["198.51.100.10|443"].failure_counter, nil,
    "ordinary SYN loss is not blamed on an action that never ran")
cases = cases + 1

seed()
local good = connection()
event(good, "syn")
event(good, "success")
event(good, "retrans"); event(good, "retrans"); event(good, "retrans")
equal(autostate.tcp_general["198.51.100.10|443"].failure_counter, nil,
    "proven success retains stock suppression of later failures")
cases = cases + 1

seed()
local original = connection()
event(original, "syn")
local before = sends
local _, reply = event(original, "reply")
equal(keen_pbr_syndata(nil, reply), VERDICT_PASS, "never modify a reply")
local _, tfo = event(connection(), "syn", nil, 8443)
equal(sends, before, "different service port must not run the SYN action")
tfo.dis.tcp.th_dport, tfo.dis.payload = 443, "existing-tfo-data"
equal(keen_pbr_syndata(nil, tfo), VERDICT_PASS, "preserve client TFO payload")
equal(sends, before, "excluded packets did not call stock syndata")
cases = cases + 1

seed()
local _, outbound = event(connection(), "syn")
local _, inbound = event(connection(), "reply")
equal(keen_pbr_tcp_endpoint(outbound), keen_pbr_tcp_endpoint(inbound), "direction-stable identity")
inbound.dis.tcp.th_sport = 8443
assert(keen_pbr_tcp_endpoint(outbound) ~= keen_pbr_tcp_endpoint(inbound), "ports share learning")
inbound.test_ip = "2001:db8::1"
equal(keen_pbr_tcp_endpoint(inbound), "2001:db8::1|8443", "IPv6 is unambiguous")
cases = cases + 1

-- TCP application retransmission/RST behavior is still owned by upstream.
seed(nil, nil, 1)
for _ = 1, 2 do
    local c = connection()
    event(c, "data"); event(c, "retrans"); event(c, "retrans")
end
equal(autostate.tcp_general["198.51.100.10|443"].nstrategy, 2, "data retransmission still rotates")
local c = connection()
event(c, "data"); event(c, "rst")
equal(autostate.tcp_general["198.51.100.10|443"].failure_counter, 1, "incoming RST still counts")
cases = cases + 1

seed(nil, nil, 1)
event(connection(), 'http')
equal(table.concat(executed, ','), 'fake,http_methodeol', 'HTTP actions bypass the circular handshake plan')
event(connection(), 'reply')
equal(#executed, 0, 'replies are observed without applying any outbound action')
cases = cases + 1

print("nfqws TCP SYN semantics passed: " .. cases .. " scenarios")
