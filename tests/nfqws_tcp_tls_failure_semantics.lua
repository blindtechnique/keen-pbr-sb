-- Real upstream circular and production detectors; packet delivery is modeled.
-- A separate native NFQUEUE/NAT test is required for directional identity.
local fixture, companion, profiles = assert(arg[1]), assert(arg[2]), assert(arg[3])
VERDICT_PASS, TH_SYN, TH_RST, TH_ACK = 0, 2, 4, 16
function DLOG() end
function DLOG_ERR() end
function ntop(address) return address end
function pos_get(d) return d.sequence end
function is_retransmission(d) return d.retransmit or false end
function bitand(a, b)
    local result, place = 0, 1
    while a > 0 and b > 0 do
        if a % 2 == 1 and b % 2 == 1 then result = result + place end
        a, b, place = math.floor(a / 2), math.floor(b / 2), place * 2
    end
    return result
end
function orchestrate() end
function plan_instance_pop(d) return table.remove(d.plan, 1) end
function plan_instance_execute(d, verdict, instance)
    d.selected = tonumber(instance.arg.strategy)
    return verdict
end
function rawsend_dissect() error('Detector tests must not send packets') end
dofile(fixture .. '/zapret-lib-host-ip.lua')
dofile(arg[4] or (fixture .. '/zapret-auto.lua'))
local real_io = io
io = nil
dofile(companion)
io = real_io
local file = assert(io.open(profiles .. '/03 max/nfqws2.conf', 'rb'))
local text = assert(file:read('*a'))
file:close()
local general = assert(text:match('NFQWS_ARGS="(.-)"'))
local token = assert(general:match('%-%-lua%-desync=circular:([^%s]+)'))
local options, slots = {}, {}
for key, value in token:gmatch('([^:=]+)=([^:]+)') do options[key] = value end
for slot in general:gmatch(':strategy=(%d+)') do slots[tonumber(slot)] = true end
assert(options.key == 'tcp_general' and options.fails == '2')
assert(options.failure_detector == 'keen_pbr_syn_failure_detector')
local checks = 0
local function equal(actual, expected, label)
    checks = checks + 1
    assert(actual == expected, label .. ': expected ' .. tostring(expected) .. ', got ' .. tostring(actual))
end
local function fresh()
    return {lua_state={}, pos={client={tcp={seq0=100000, uppos=2155}}, server={tcp={}}}}
end
local function packet(track, payload, seq, outgoing, override)
    local d = {track=track, outgoing=outgoing or false, sequence=seq,
        func_instance='test-general', target={ip='198.51.100.10'}, arg={}, plan={},
        l7payload=outgoing and 'tls_client_hello' or 'unknown', l7proto='tls',
        dis={payload=payload, tcp={th_flags=24, th_ack=102155,
            th_sport=outgoing and 40000 or 443, th_dport=outgoing and 443 or 40000}}}
    for k,v in pairs(options) do d.arg[k]=v end
    for i=1,#slots do d.plan[i]={arg={strategy=tostring(i)}} end
    if override then override(d) end
    circular(nil, d)
    local host = autostate.tcp_general and autostate.tcp_general[keen_pbr_tcp_endpoint(d)]
    return host, track.lua_state.automate, d
end
local hello = string.char(22,3,1,0,4,1,0,0,0) -- descriptor is supplied by the engine
local fatal = string.char(21,3,3,0,2,2,50)
local close = string.char(21,3,3,0,2,1,0)
local function arm(track, override) return packet(track, hello, 1, true, override) end
local function reset() autostate={} end

reset()
local c = fresh()
arm(c)
local host, connection = packet(c, fatal, 1)
equal(host.failure_counter, 1, 'early fatal is one failure')
equal(host.nstrategy, 1, 'one failure does not skip threshold')
equal(connection.nocheck, true, 'stock closes observation after failure')
packet(c, fatal, 1) -- retransmission must not become another failure
packet(c, close, 8)
packet(c, '', 2155, true, function(d) d.dis.tcp.th_flags=17 end)
equal(host.failure_counter, 1, 'alert retry, close_notify and FIN cannot double count')
local second = fresh()
arm(second)
host = packet(second, fatal, 1)
equal(host.nstrategy, 2, 'second failed connection rotates')
equal(host.failure_counter, nil, 'stock resets counter on rotation')
local _, _, next_packet = arm(fresh())
equal(next_packet.selected, 2, 'next connection uses new choice')

for split=1,6 do
    for _, reverse in ipairs({false,true}) do
        reset()
        c=fresh(); arm(c)
        local first, last=fatal:sub(1,split),fatal:sub(split+1)
        if reverse then
            host=packet(c,last,split+1)
            equal(host.failure_counter,nil,'out-of-order tail waits')
            host=packet(c,first,1)
        else
            host=packet(c,first,1)
            equal(host.failure_counter,nil,'partial header waits')
            packet(c,first,1)
            host=packet(c,last,split+1)
        end
        equal(host.failure_counter,1,'segmented alert counts once')
        equal(c.lua_state.automate.keen_pbr_tls_alert,false,'seven-byte buffer released')
    end
end
reset()
c=fresh(); arm(c)
packet(c,fatal:sub(1,3),1)
host=packet(c,fatal:sub(3),3)
equal(host.failure_counter,1,'matching overlap supported')
for version=1,3 do
    reset(); c=fresh(); arm(c)
    host=packet(c,fatal:sub(1,2)..string.char(version)..fatal:sub(4)..close,1,false,
        function(d) d.dis.tcp.th_flags=25 end)
    equal(host.failure_counter,1,'coalesced record and FIN, TLS record version '..version)
end

local negatives = {
    {'close_notify',close},
    {'warning decode_error',string.char(21,3,3,0,2,1,50)},
    {'handshake_failure',string.char(21,3,3,0,2,2,40)},
    {'certificate_unknown',string.char(21,3,3,0,2,2,46)},
    {'SSL3 record',string.char(21,3,0,0,2,2,50)},
    {'invalid version',string.char(21,3,4,0,2,2,50)},
    {'invalid major',string.char(21,4,3,0,2,2,50)},
    {'invalid short length',string.char(21,3,3,0,1,2,50)},
    {'invalid long length',string.char(21,3,3,0,3,2,50,0)},
    {'server handshake',string.char(22,3,3,0,2,2,50)},
    {'encrypted record containing alert',string.char(23,3,3,0,7)..fatal},
    {'truncated alert',fatal:sub(1,6)},
    {'empty',''},
}
for _,case in ipairs(negatives) do
    reset(); c=fresh(); arm(c)
    host,connection=packet(c,case[2],1)
    equal(host.failure_counter,nil,case[1]..' is not counted')
    equal(connection.nocheck,nil,case[1]..' is not artificial success/failure')
end
for _,seq in ipairs({-1,0,1.5,8,26001}) do
    reset(); c=fresh(); arm(c)
    host=packet(c,fatal,seq)
    equal(host.failure_counter,nil,'not first TLS record at seq '..seq)
end
reset(); c=fresh()
host=packet(c,fatal,1)
equal(host.failure_counter,nil,'unobserved ClientHello cannot arm detector')
reset(); c=fresh()
arm(c,function(d) d.l7payload='mtproto_initial'; d.l7proto='mtproto' end)
host=packet(c,fatal,1)
equal(host.failure_counter,nil,'MTProto is not TLS')
reset(); c=fresh()
arm(c,function(d) d.l7payload='http_req'; d.l7proto='http' end)
host=packet(c,fatal,1)
equal(host.failure_counter,nil,'HTTP is not TLS')

-- Another first server record permanently disarms recognition, even if a
-- later reply carries matching plaintext-like bytes at a suspicious offset.
for _,record in ipairs({close,string.char(22,3,3,0,2,2,0),string.char(23,3,3,0,2,2,0)}) do
    reset(); c=fresh(); arm(c)
    packet(c,record,1)
    arm(c) -- a retry/HRR must not rearm an already disarmed connection
    host=packet(c,fatal,1)
    equal(host.failure_counter,nil,'do not rescan after a different server record')
end
reset(); c=fresh(); arm(c)
packet(c,fatal:sub(1,2)..string.char(1),1)
host=packet(c,fatal,1)
equal(host.failure_counter,nil,'conflicting overlap is not decoded')
for _,side in ipairs({'client','server'}) do
    reset(); c=fresh(); arm(c)
    c.pos[side].tcp.rseq_over_2G=true
    host=packet(c,fatal,1)
    equal(host.failure_counter,nil,'ignore wrapped '..side..' stream')
end
reset(); c=fresh(); arm(c)
host=packet(c,'successful server data',26001)
equal(c.lua_state.automate.nocheck,true,'real success still closes observation')
host=packet(c,fatal,1)
equal(host.failure_counter,nil,'alert after established success ignored')
reset(); c=fresh(); arm(c)
host=packet(c,fatal,1,true)
equal(host.failure_counter,nil,'outgoing alert not counted')

reset(); c=fresh()
local other_pool=function(d) d.arg.key='another_tcp_pool' end
arm(c,other_pool); packet(c,fatal,1,false,other_pool)
equal(autostate.another_tcp_pool['198.51.100.10|443'].failure_counter,nil,'other pool unchanged')
reset()
for _,port in ipairs({443,8443}) do
    c=fresh()
    local service=function(d)
        if d.outgoing then d.dis.tcp.th_dport=port else d.dis.tcp.th_sport=port end
    end
    arm(c,service); packet(c,fatal,1,false,service)
    equal(autostate.tcp_general['198.51.100.10|'..port].failure_counter,1,'service port isolated')
end
reset()
for _,ip in ipairs({'198.51.100.10','198.51.100.11','2001:db8::10'}) do
    c=fresh()
    local address=function(d) d.target.ip=ip end
    arm(c,address); packet(c,fatal,1,false,address)
    equal(autostate.tcp_general[ip..'|443'].failure_counter,1,'address key isolated')
end
print('TCP early TLS failure semantics: '..checks..' checks passed')
