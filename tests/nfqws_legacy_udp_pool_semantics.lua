local auto_path = assert(arg[1], "pinned zapret-auto.lua path is required")
local strategies = assert(arg[2], "packaged strategy directory is required")

-- Execute the exact pinned circular/detector code. These shims model nfqws
-- packet positions and documented per-instance payload/range filters; no
-- fake packet is sent and no router or live configuration is involved.
b_debug = false
VERDICT_PASS = 0
function DLOG(_) end
function DLOG_ERR(message) error(message) end
function dissect_nld(host, _) return host end
function host_ip(_) return "198.51.100.4" end
function orchestrate(_, _) end
function plan_instance_pop(desync) return table.remove(desync.plan, 1) end
function pos_get(desync, kind, reverse)
    assert(kind == "n", "UDP detector must use packet positions")
    if reverse == nil then reverse = not desync.outgoing end
    return reverse and desync.track.incoming or desync.track.outgoing
end

local function contains(csv, value)
    for item in csv:gmatch("[^,]+") do
        if item == value then return true end
    end
    return false
end

local function in_range(range, position)
    if range == "a" then return true end
    if range == "x" then return false end
    local inclusive = range:match("^%-n(%d+)$")
    if inclusive then return position <= tonumber(inclusive) end
    local exclusive = range:match("^<n(%d+)$")
    assert(exclusive, "fixture encountered an unsupported range: " .. range)
    return position < tonumber(exclusive)
end

local function accepts(instance, desync)
    local range = desync.outgoing and instance.out_range or instance.in_range
    return in_range(range, pos_get(desync, "n")) and
        (instance.payload == "all" or contains(instance.payload, desync.l7payload))
end

function plan_instance_execute(desync, verdict, instance)
    if accepts(instance, desync) then
        desync.executed[#desync.executed + 1] = instance.body
    end
    return verdict
end

assert(loadfile(auto_path))()

local profiles = {
    {"default", "default", false}, {"ver1", "ver1", false},
    {"ver1 (alt)", "ver1_alt", true}, {"ver2", "ver2", true},
    {"ver3 safe", "ver3_safe", true}, {"ver4", "ver4", true},
}
local pools = {}
local host = "same.example"

local function parse_pool(profile, variable, key, protocol)
    local input = assert(io.open(strategies .. "/" .. profile .. "/nfqws2.conf", "rb"))
    local content = assert(input:read("*a"))
    input:close()
    local value = assert(content:match(variable .. '="([^"]*)"'))
    local pool = {key = key, protocol = protocol, instances = {}}
    local payload, out_range, incoming_range = "all", "a", "x"
    for token in value:gmatch("%S+") do
        local name, option = token:match("^%-%-([%w%-]+)=(.*)$")
        if name == "filter-udp" then pool.ports = option
        elseif name == "filter-l7" then pool.l7 = option
        elseif name == "payload" then payload = option
        elseif name == "out-range" then out_range = option
        elseif name == "in-range" then incoming_range = option
        elseif name == "lua-desync" then
            local instance = {
                body = option, arg = {}, payload = payload,
                out_range = out_range, in_range = incoming_range,
            }
            instance.func = option:match("^[^:]+")
            for argument, argument_value in option:gmatch(":([%w_]+)=([^:]+)") do
                instance.arg[argument] = argument_value
            end
            pool.instances[#pool.instances + 1] = instance
        end
    end
    assert(#pool.instances == 3, "expected circular and two distinct choices")
    local detector = pool.instances[1]
    assert(detector.func == "circular" and detector.arg.key == key)
    assert(detector.payload == "all" and detector.in_range == "-n2")
    assert(detector.out_range == (protocol == "quic" and "a" or "-n4"))
    assert(detector.arg.udp_out == "4" and detector.arg.udp_in == "1")
    assert(not detector.arg.retrans, "TCP retransmission knob has no UDP meaning")
    for index = 2, 3 do
        local action = pool.instances[index]
        assert(action.arg.strategy == tostring(index - 1))
        assert(action.in_range == "x", "responses must be observation-only")
        assert(action.out_range == (protocol == "quic" and "a" or "<n2"))
    end
    return pool
end

for _, profile in ipairs(profiles) do
    for _, protocol in ipairs(profile[3] and {"quic", "udp"} or {"quic"}) do
        pools[#pools + 1] = parse_pool(
            profile[1], protocol == "quic" and "NFQWS_ARGS_QUIC" or "NFQWS_ARGS_UDP",
            "legacy_" .. profile[2] .. "_" .. protocol, protocol)
    end
end
assert(#pools == 10)

local function new_track()
    return {hostname = host, lua_state = {}, outgoing = 0, incoming = 0}
end

local function port_matches(spec, port)
    for segment in spec:gmatch("[^,]+") do
        local first, last = segment:match("^(%d+)%-(%d+)$")
        if first then
            if port >= tonumber(first) and port <= tonumber(last) then return true end
        elseif tonumber(segment) == port then return true end
    end
    return false
end

local function packet(pool, track, outgoing, position, payload, port, l7)
    local field = outgoing and "outgoing" or "incoming"
    track[field] = position
    local desync = {
        arg = pool.instances[1].arg, track = track,
        dis = {udp = {}, payload = "fixture"}, outgoing = outgoing,
        l7payload = payload, func_instance = pool.key, plan = {}, executed = {},
    }
    if not port_matches(pool.ports, port or (pool.protocol == "quic" and 443 or 3478)) or
        not contains(pool.l7, l7 or (pool.protocol == "quic" and "quic" or "stun")) then
        return desync.executed, false
    end
    for index = 2, #pool.instances do
        desync.plan[#desync.plan + 1] = pool.instances[index]
    end
    local observed = accepts(pool.instances[1], desync)
    if observed then
        circular(nil, desync)
    else
        -- C resumes the ordinary linear plan when circular's own filters do
        -- not match. This catches the late-QUIC double-action regression.
        for _, instance in ipairs(desync.plan) do
            plan_instance_execute(desync, VERDICT_PASS, instance)
        end
    end
    return desync.executed, observed
end

local function record(pool) return assert(autostate[pool.key][host]) end
local function original_payload(pool)
    return pool.protocol == "quic" and "quic_initial" or "stun"
end
local function fail_session(pool)
    local track = new_track()
    for position = 1, 4 do
        local actions, observed = packet(pool, track, true, position, original_payload(pool))
        assert(observed, "detector missed outgoing failure window")
        assert(#actions == ((pool.protocol == "quic" or position == 1) and 1 or 0))
    end
end

autostate = {}
for _, pool in ipairs(pools) do
    local actions = packet(pool, new_track(), true, 1, original_payload(pool))
    assert(#actions == 1 and actions[1] == pool.instances[2].body)
end
for _, pool in ipairs(pools) do
    fail_session(pool)
    assert(record(pool).nstrategy == 1 and record(pool).failure_counter == 1)
    fail_session(pool)
    assert(record(pool).nstrategy == 2, "second failed session must rotate")
    for _, other in ipairs(pools) do
        if other ~= pool then assert(record(other).nstrategy == 1, "pool key leaked") end
    end
    local late, observed = packet(pool, new_track(), true, 5, original_payload(pool))
    if pool.protocol == "quic" then
        assert(observed and #late == 1 and late[1] == pool.instances[3].body)
    else
        assert(not observed and #late == 0, "UDP action escaped its old range")
        fail_session(pool)
    end
    assert(record(pool).failure_counter == 1)
    local success = new_track()
    for position = 1, 2 do
        local actions, saw_reply = packet(pool, success, false, position, "unknown")
        assert(saw_reply and #actions == 0, "reply must reach only the detector")
    end
    assert(record(pool).failure_counter == nil and record(pool).nstrategy == 2)
    local actions, saw_late_reply = packet(pool, success, false, 3, "unknown")
    assert(not saw_late_reply and #actions == 0)
    fail_session(pool)
    fail_session(pool)
    assert(record(pool).nstrategy == 1, "rotation must wrap from slot 2 to slot 1")
    local wrong_payload = packet(pool, new_track(), true, 1, "unrelated_payload")
    local wrong_port = packet(pool, new_track(), true, 1, original_payload(pool), 53)
    local wrong_protocol = packet(pool, new_track(), true, 1, original_payload(pool), nil, "unknown")
    assert(#wrong_payload == 0 and #wrong_port == 0 and #wrong_protocol == 0)
end
print("legacy UDP/QUIC circular semantics passed: 10 independent pools; failure, reply, wrap, late-packet and action-filter checks")
