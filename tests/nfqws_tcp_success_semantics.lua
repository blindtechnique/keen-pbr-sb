local fixture, companion = assert(arg[1]), assert(arg[2])
VERDICT_PASS, TH_SYN, TH_RST, TH_ACK = 0, 2, 4, 16
b_debug = false
function DLOG(_) end
function DLOG_ERR(_) end
function bitand(a, b)
    local result, place = 0, 1
    while a > 0 and b > 0 do
        if a % 2 == 1 and b % 2 == 1 then result = result + place end
        a, b, place = math.floor(a/2), math.floor(b/2), place*2
    end
    return result
end
function pos_get(d, _) return d.sequence end
function is_retransmission(d) return d.retransmit or false end
dofile(fixture .. '/zapret-auto.lua')
local real_io = io
io = nil
dofile(companion)
io = real_io

local count = 0
local function check(value, expected, label)
    assert(value == expected, label .. ': got ' .. tostring(value))
    count = count + 1
end
local function packet(outgoing, seq, ack, payload, flags)
    return {outgoing=outgoing, sequence=seq,
        arg={maxseq='65536', inseq='26000', retrans='2', fails='2',
             success_detector='keen_pbr_tcp_success_detector'},
        track={pos={client={tcp={seq0=1000, uppos=70000}}}},
        dis={tcp={th_flags=flags or TH_ACK, th_ack=ack}, payload=payload or ''}}
end
local function success(d) return keen_pbr_tcp_success_detector(d, {}) end
check(success(packet(true, 66900, nil, 'client data')), false, 'sending beyond maxseq proves nothing')
check(success(packet(false, 27000, nil, 'server data')), true, 'received data past threshold')
check(success(packet(false, 27000, nil)), false, 'empty server packet is not downloaded data')
check(success(packet(false, 1, 68000)), true, 'ACK confirms observed upload')
check(success(packet(false, 1, 91000)), false, 'ACK beyond observed client bytes ignored')
check(success(packet(false, 1, 66536)), false, 'threshold is strict')
check(success(packet(false, 27000, 68000, 'data', TH_RST+TH_ACK)), false, 'RST is never success')
check(success(packet(false, 27000, 68000, 'data', TH_SYN+TH_ACK)), false, 'SYN ACK is never success')
check(success(packet(false, 27000, 68000, 'data', 1+TH_ACK)), false, 'FIN not success')
local wrapped = packet(false, 1, 66000)
wrapped.track.pos.client.tcp.seq0 = 4294966000
check(success(wrapped), true, '32-bit initial sequence wrap handled')
wrapped.track.pos.client.tcp.rseq_over_2G = true
check(success(wrapped), false, 'wrapped long-lived counters not used')
local unknown = packet(false, 1, 68000)
unknown.track.pos.client.tcp.seq0 = nil
check(success(unknown), false, 'missing sequence reference is not success')
local stale = packet(false, 1, 900)
check(success(stale), false, 'ACK behind initial sequence is not success')

-- Real stock failure-counter arbitration: outgoing >maxseq used to erase
-- previous failures and set nocheck before the late retransmission arrived.
local host_record, connection = {nstrategy=1, failure_counter=1}, {}
local sent = packet(true, 66900, nil, 'request')
automate_failure_check(sent, host_record, connection)
check(connection.nocheck, nil, 'large send does not close failure observation')
check(host_record.failure_counter, 1, 'large send does not erase prior failure')
local retry = packet(true, 18000, nil, 'retransmitted request')
retry.retransmit = true
automate_failure_check(retry, host_record, connection)
check(automate_failure_check(retry, host_record, connection), true, 'late retry completes fails=2')
check(connection.nocheck, true, 'one failure per connection remains stock owned')
print('TCP confirmed-success semantics: ' .. count .. ' checks passed')
