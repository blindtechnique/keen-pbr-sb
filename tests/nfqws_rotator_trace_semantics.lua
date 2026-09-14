local fixture, companion, observer, profiles = assert(arg[1]), assert(arg[2]), assert(arg[3]), assert(arg[4])
-- Exact stock circular/failure code; packet execution and the clock are controlled.
-- This is not a TLS/DPI or browser emulator.
VERDICT_PASS, TH_SYN, TH_RST, TH_ACK = 0, 2, 4, 16
b_debug = false
function DLOG(_) end
function DLOG_ERR(_) end
function ntop(address) return address end
function bitand(a, b)
    local result, place = 0, 1
    while a > 0 and b > 0 do
        if a % 2 == 1 and b % 2 == 1 then result = result + place end
        a, b, place = math.floor(a / 2), math.floor(b / 2), place * 2
    end
    return result
end
function seq_ge(a, b) return a >= b end
function pos_get(d, _) return d.sequence end
function orchestrate(_, _) end
function plan_instance_pop(d) return table.remove(d.plan, 1) end
function plan_instance_execute(d, verdict, instance)
    -- In zapret-lib this overwrites d.arg before the action's payload/range filter.
    d.arg = instance.arg
    d.requested_slot = tonumber(instance.arg.strategy)
    return verdict
end
local raw_sends = 0
function rawsend_dissect() raw_sends = raw_sends + 1 end
local now = 2000000000
os.time = function() return now end
dofile(fixture .. '/zapret-lib-host-ip.lua')
dofile(fixture .. '/zapret-lib-is-retransmission.lua')
dofile(arg[5] or fixture .. '/zapret-auto.lua')
local saved_io = io
io = nil
dofile(companion)
io = saved_io

local checks = 0
local function equal(actual, expected, label)
    assert(actual == expected, label .. ': expected ' .. tostring(expected) .. ', got ' .. tostring(actual))
    checks = checks + 1
end
local function copy(value)
    if type(value) ~= 'table' then return value end
    local result = {}
    for k, v in pairs(value) do result[k] = copy(v) end
    return result
end
local function stable(value)
    if type(value) ~= 'table' then return tostring(value) end
    local keys, result = {}, {}
    for key in pairs(value) do keys[#keys + 1] = key end
    table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
    for _, key in ipairs(keys) do result[#result + 1] = tostring(key) .. '=' .. stable(value[key]) end
    return '{' .. table.concat(result, ',') .. '}'
end
local originals = {circular, automate_host_record, automate_failure_check}
dofile(observer)
equal(circular, originals[1], 'loading observer does not hook circular')
equal(automate_host_record, originals[2], 'loading observer does not hook host state')
equal(automate_failure_check, originals[3], 'loading observer does not hook detectors')
local api = assert(keen_pbr_rotator_trace, 'opt-in trace API is missing')
local handle = assert(io.open(profiles .. '/03 max/nfqws2.conf', 'rb'))
local config = assert(handle:read('*a'))
handle:close()
local block = assert(config:match('NFQWS_ARGS="(.-)"'))
local general_options, slots = {}, {}
for key, value in assert(block:match('%-%-lua%-desync=circular:([^%s]+)')):gmatch('([%w_]+)=([^:]+)') do
    general_options[key] = value
end
for slot in block:gmatch(':strategy=(%d+)') do slots[tonumber(slot)] = true end
equal(general_options.fails, '2', 'real Max failure threshold')
equal(general_options.retrans, '2', 'real Max retransmission threshold')
equal(general_options.reset, nil, 'real Max does not reset stalled general connections')
equal(general_options.hostkey, 'keen_pbr_tcp_endpoint', 'real Max endpoint key')
equal(#slots, 12, 'real Max strategy count')
local rows = {}
local function options(extra)
    local o = {client='192.0.2.10', targets={'198.51.100.10|443', '198.51.100.11|443'},
        pool='tcp_general', seconds=120, max_events=512,
        emit=function(row) rows[#rows + 1] = copy(row) end}
    for k, v in pairs(extra or {}) do o[k] = v end
    return o
end
local function begin(extra)
    rows = {}
    return assert(api.start(options(extra)))
end
local serial = 0
local function connection(remote, client)
    serial = serial + 1
    return {client=client or '192.0.2.10', remote=remote or '198.51.100.10',
        port=40000 + serial, hostname='page.example', lua_state={},
        pos={direct={tcp={}}, client={tcp={seq0=1000, uppos=2200}}}}
end
local function event(track, kind, overrides)
    local incoming = kind == 'success' or kind == 'reply' or kind == 'rst'
    local seq = kind == 'success' and 27000 or kind == 'large-send' and 67000 or 1
    local ip6 = track.client:find(':', 1, true) ~= nil
    local payload = incoming and (kind == 'rst' and '' or 'reply') or 'clienthello'
    track.pos.direct.tcp = {uppos_prev=kind == 'retry' and seq or seq - 1, pos=seq}
    local d = {outgoing=not incoming, sequence=seq, track=track,
        target={ip=not ip6 and track.remote or nil, ip6=ip6 and track.remote or nil},
        arg=copy(general_options),
        func_instance='circular_1', l7payload=incoming and 'tls_server_hello' or 'tls_client_hello',
        dis={tcp={th_flags=kind == 'rst' and TH_RST or TH_ACK,
            th_sport=incoming and 443 or track.port, th_dport=incoming and track.port or 443},
            payload=payload}, plan={}}
    local src, dst = incoming and track.remote or track.client, incoming and track.client or track.remote
    if ip6 then d.dis.ip6 = {ip6_src=src, ip6_dst=dst}
    else d.dis.ip = {ip_src=src, ip_dst=dst} end
    for i = 1, #slots do d.plan[i] = {arg={strategy=tostring(i)}} end
    for k, v in pairs(overrides or {}) do d[k] = v end
    local verdict = circular(nil, d)
    return d.requested_slot, verdict, d
end
local function hrec(remote)
    return autostate.tcp_general[(remote or '198.51.100.10') .. '|443']
end
local function fail(track)
    event(track, 'original')
    event(track, 'retry')
    return event(track, 'retry')
end
local function reset()
    autostate = {}
    now = 2000000000
    raw_sends = 0
end

-- Contract for the real two-connection, no-reset general pool.
local function stalled_sequence()
    local a, b = connection(), connection()
    local result = {}
    local function record(track, kind)
        local selected, verdict = event(track, kind)
        result[#result + 1] = {selected=selected, verdict=verdict}
        return selected
    end
    local function stalled(track)
        record(track, 'original')
        record(track, 'retry')
        record(track, 'retry')
    end
    stalled(a)
    equal(hrec().failure_counter, 1, 'first connection contributes exactly one failure')
    now = now + 23
    for _ = 1, 4 do record(a, 'retry') end
    equal(hrec().nstrategy, 1, 'waiting and more retries do not rotate after nocheck')
    record(a, 'success')
    equal(hrec().failure_counter, 1, 'late same-connection success is no longer checked')
    stalled(b)
    equal(hrec().nstrategy, 2, 'second failing connection rotates shared choice')
    record(a, 'retry')
    equal(result[#result].selected, 2, 'old connection uses new shared slot on its next packet')
    equal(a.lua_state.automate.nocheck, true, 'old connection remains unchecked after switching slot')
    equal(hrec().failure_counter, nil, 'old connection cannot count another failure for slot 2')
    equal(raw_sends, 0, 'diagnosis does not inject resets')
    return stable({state=autostate, a=a.lua_state, b=b.lua_state, packets=result})
end
reset()
local baseline = stalled_sequence()
reset()
local session = begin()
equal(stalled_sequence(), baseline, 'observer preserves verdicts, selected slots and all production state')
equal(rows[3].check, 'failure', 'failure event is explicit')
equal(rows[3].reason, 'tcp_retransmissions', 'failure reason comes from actual detector counters')
equal(rows[4].check, 'already_finished', 'further retransmission has no detector execution')
equal(rows[8].check, 'already_finished', 'late reply is not reported as verified success')
equal(rows[11].slot_before, 1, 'rotation records old host slot')
equal(rows[11].slot_after, 2, 'rotation records new host slot')
equal(rows[12].previous_selected, 1, 'connection remembers previous observed selection only in trace')
equal(rows[12].slot_after, 2, 'already failed connection now sees shared slot 2')
equal(rows[12].check, 'already_finished', 'new slot did not reactivate its failure detector')
equal(rows[12].first_selected, 1, 'first selection remains available for attribution')
session.stop()
equal(circular, originals[1], 'stop restores circular')

reset()
session = begin()
fail(connection())
local healthy = connection()
event(healthy, 'reply')
equal(rows[#rows].check, 'pending', 'small TLS reply is not complete-response success')
event(healthy, 'large-send')
equal(rows[#rows].check, 'pending', 'attempted upload is not success')
event(healthy, 'success')
equal(rows[#rows].check, 'success', 'fresh connection may report detector success')
equal(hrec().failure_counter, nil, 'fresh success clears pending shared failure')
event(connection('198.51.100.11'), 'original')
equal(rows[#rows].slot_after, 1, 'a different CDN address starts independently')
autostate = {}
event(connection(), 'original')
equal(rows[#rows].slot_after, 1, 'cleared RAM state starts general pool at 1, not a saved winner')
session.stop()

reset()
fail(connection())
now = now + 301
session = begin()
fail(connection())
equal(hrec().nstrategy, 1, '300 seconds is the failure accumulation window, not a per-slot timer')
equal(rows[#rows].counter_expired, true, 'trace identifies expired previous failure')
session.stop()

-- Other clients can affect a shared endpoint but must not leak into this trace.
reset()
session = begin()
fail(connection())
local before_count = #rows
event(connection(nil, '192.0.2.11'), 'success')
equal(#rows, before_count, 'different client is not logged')
equal(hrec().failure_counter, nil, 'non-traced client still has unchanged production effect')
event(connection('198.51.100.99'), 'original')
equal(#rows, before_count, 'different remote target is not logged')
local nat = connection()
event(nat, 'original')
event(nat, 'reply', {dis={ip={ip_src=nat.remote, ip_dst='192.0.2.254'},
    tcp={th_flags=16, th_sport=443, th_dport=nat.port}, payload='reply'}})
equal(rows[#rows].direction, 'in', 'known exact conntrack can observe a pre-DNAT reply')
equal(rows[#rows].client, '192.0.2.10', 'NAT fallback uses only the already matched conntrack')
session.stop()

reset()
session = begin({client='2001:db8::10', targets={'2001:db8::20|443'}})
local v6 = connection('2001:db8::20', '2001:db8::10')
event(v6, 'original')
event(v6, 'reply')
equal(#rows, 2, 'IPv6 matches both directions')
session.stop()

reset()
session = begin({max_connections=1})
event(connection(), 'original')
equal(event(connection(), 'original'), 1, 'connection limit does not affect real selection')
equal(session.status().reason, 'connection_limit', 'bounded trace-owned connection metadata')
equal(#rows, 1, 'no rows allocated for additional connections')

reset()
local hostkey_calls, real_hostkey = 0, keen_pbr_tcp_endpoint
keen_pbr_tcp_endpoint = function(d) hostkey_calls = hostkey_calls + 1; return real_hostkey(d) end
fail(connection())
local baseline_hostkey_calls = hostkey_calls
hostkey_calls = 0
session = begin()
fail(connection())
equal(hostkey_calls, baseline_hostkey_calls, 'observer never invokes hostkey or detectors a second time')
local reloaded = dofile(observer)
equal(reloaded, api, 'reloading observer retains one API/session')
equal(reloaded.start(options()), nil, 'reloading cannot double-wrap the active session')
session.stop()
keen_pbr_tcp_endpoint = real_hostkey

reset()
session = begin()
local secret_track = connection()
secret_track.hostname = 'private-hostname.example'
local secret_payload = 'Authorization: never-record-this-payload'
event(secret_track, 'original', {dis={ip={ip_src=secret_track.client, ip_dst=secret_track.remote},
    tcp={th_flags=16, th_sport=secret_track.port, th_dport=443}, payload=secret_payload}})
equal(stable(rows):find('never-record-this-payload', 1, true), nil, 'payload content never enters a trace row')
equal(stable(rows):find('private-hostname', 1, true), nil, 'hostname is not collected implicitly')
equal(rows[1].payload_bytes, #secret_payload, 'only payload length is recorded')
session.stop()

-- Observer resource/error paths must never stop or alter the real orchestrator.
reset()
session = begin({max_events=1})
local limited = connection()
event(limited, 'original')
equal(session.status().reason, 'event_limit', 'bounded event count stops trace')
equal(circular, originals[1], 'limit restores production functions')
fail(limited)
equal(#rows, 1, 'no writes after event limit')
session = begin({seconds=1})
now = now + 2
event(connection(), 'original')
equal(session.status().reason, 'expired', 'deadline stops trace without needing an I/O timer')
equal(#rows, 0, 'expired trace emits nothing')
session = begin()
now = now - 1
event(connection(), 'original')
equal(session.status().reason, 'clock_changed', 'backwards clock cannot extend capture')
session = begin()
now = now + 5
event(connection(), 'original')
now = now - 1
event(connection(), 'original')
equal(session.status().reason, 'clock_changed', 'clock regression after initial progress also stops capture')
equal(#rows, 1, 'no additional row after clock regression')
session = begin({emit=function() error('disk unavailable') end})
local slot, verdict = event(connection(), 'original')
equal(verdict, VERDICT_PASS, 'sink error cannot change packet verdict')
equal(session.status().reason, 'sink_error', 'sink failure disables only trace')
equal(circular, originals[1], 'sink failure unhooks trace')
equal(raw_sends, 0, 'all observer failure paths remain non-sending')

local invalid = options({targets={}})
equal(api.start(invalid), nil, 'unscoped target selection is refused')
equal(api.start(options({client=''})), nil, 'unscoped client selection is refused')
equal(api.start(options({seconds=301})), nil, 'duration cannot exceed five minutes')
equal(api.start(options({max_events=2049})), nil, 'event bound cannot be enlarged arbitrarily')
session = begin()
equal(api.start(options()), nil, 'cannot double-wrap an active session')
local newer_hook = function() return 91 end
circular = newer_hook
session.stop()
equal(circular, newer_hook, 'stop never overwrites a later unrelated hook')
circular = originals[1]

local marker = {}
circular = function() error(marker) end
session = begin()
local ok, err = pcall(event, connection(), 'original')
equal(ok, false, 'original errors remain errors')
equal(err, marker, 'original error object is preserved')
session.stop()
local d
-- Reuse a well-formed packet from the normal engine before the multi-return stub.
circular = originals[1]
_, _, d = event(connection(), 'original')
d.arg = copy(general_options)
circular = function() return 7, nil, 9 end
session = begin()
local a, b, c = circular(nil, d)
equal(a, 7, 'first return is preserved')
equal(b, nil, 'nil return position is preserved')
equal(c, 9, 'multiple return values are preserved')
equal(#rows, 1, 'multi-return test exercised the selected trace path, not just passthrough')
session.stop()
circular = originals[1]

local rendered = api.format({time=123, pool='bad\tpool\n', reason='x\000y'})
equal(rendered:find('\tpool\n', 1, true), nil, 'formatter cannot inject rows through text fields')
equal(rendered:find('\000', 1, true), nil, 'formatter removes control bytes')
print('TCP general retry and opt-in trace semantics: ' .. checks .. ' checks passed')
