-- Opt-in, test/acceptance-only observer. NOT loaded by presets or packaged init.
-- Load after zapret-auto.lua and our telemetry companion; then explicitly start.
-- No file I/O, timers, packet sends, detector calls or production-state writes.
if type(keen_pbr_rotator_trace) == 'table' and keen_pbr_rotator_trace.version == 1 then
    return keen_pbr_rotator_trace -- do not create a second session by reloading this file
end
local api = {version = 1}
local active_session
local unpack_values = table.unpack or unpack
local function pack(...) return {n=select('#', ...), ...} end
local function integer(n, lo, hi)
    return type(n) == 'number' and n == math.floor(n) and n >= lo and n <= hi
end
local function address(s)
    return type(s) == 'string' and #s > 0 and #s <= 45 and s:match('^[%x:.]+$') ~= nil
end
local fields = {'time', 'connection', 'client', 'client_port', 'remote', 'remote_port',
    'pool', 'key_function', 'direction', 'payload_type', 'sequence', 'flags', 'payload_bytes',
    'slot_before', 'slot_after', 'first_selected', 'previous_selected', 'slot_count',
    'check', 'reason', 'failures_before', 'failures_after', 'counter_expired',
    'retrans_before', 'retrans_after', 'nocheck_before', 'nocheck_after',
    'failure_detector', 'success_detector'}
function api.header() return table.concat(fields, '\t') end
function api.format(row)
    local out = {}
    for _, key in ipairs(fields) do
        local value = row[key]
        if value == nil then value = '-' else value = tostring(value) end
        value = value:sub(1, 128):gsub('[%c]', function(c) return string.format('%%%02X', c:byte()) end)
        out[#out + 1] = value
    end
    return table.concat(out, '\t')
end

function api.start(options)
    if active_session then return nil, 'already_active' end
    if type(options) ~= 'table' or not address(options.client)
        or type(options.pool) ~= 'string' or #options.pool == 0 or #options.pool > 128
        or not options.pool:match('^[%w_.-]+$') or type(options.emit) ~= 'function'
        or type(options.targets) ~= 'table' or #options.targets == 0 or #options.targets > 8 then
        return nil, 'explicit_client_pool_targets_and_sink_required'
    end
    local seconds, max_events = options.seconds or 120, options.max_events or 512
    local max_connections = options.max_connections or 128
    if not integer(seconds, 1, 300) or not integer(max_events, 1, 2048)
        or not integer(max_connections, 1, 256) then return nil, 'invalid_bounds' end
    local targets = {}
    for index, item in pairs(options.targets) do
        if not integer(index, 1, #options.targets) or type(item) ~= 'string' then
            return nil, 'invalid_target'
        end
        local ip, port = item:match('^([%x:.]+)|(%d+)$')
        if not address(ip) or not integer(tonumber(port), 1, 65535) then return nil, 'invalid_target' end
        targets[ip .. '|' .. tostring(tonumber(port))] = true
    end
    if type(circular) ~= 'function' or type(automate_host_record) ~= 'function'
        or type(automate_failure_check) ~= 'function' or type(ntop) ~= 'function'
        or type(os) ~= 'table' or type(os.time) ~= 'function' then return nil, 'missing_primitives' end
    local clock = os.time
    local ok, started = pcall(clock)
    if not ok or not integer(started, 0, 9007199254740991) then return nil, 'clock_unavailable' end
    local last_at = started
    local client, pool, emit = options.client, options.pool, options.emit
    local originals = {circular=circular, automate_host_record=automate_host_record,
        automate_failure_check=automate_failure_check}
    local wrappers, current = {}, nil
    -- lua_state, not the per-packet desync.track wrapper, identifies a conntrack.
    -- Weak keys and a hard allocation count bound trace-owned memory only.
    local connections = setmetatable({}, {__mode='k'})
    local session = {active=true, events=0, connection_count=0, reason='active'}
    active_session = session
    local function stop(reason)
        if not session.active then return end
        session.active, session.reason = false, reason or 'stopped'
        for name, wrapped in pairs(wrappers) do
            if _G[name] == wrapped then _G[name] = originals[name] end
        end
        connections = setmetatable({}, {__mode='k'})
        if active_session == session then active_session = nil end
    end
    local function observe(fn, ...)
        if not session.active then return end
        local observed, result = pcall(fn, ...)
        if not observed then stop('observer_error'); return end
        return result
    end
    local function snapshot(hrec, crec)
        return {slot=hrec.nstrategy, slots=hrec.ctstrategy, failures=hrec.failure_counter or 0,
            failure_time=hrec.failure_time_last, retrans=crec.retrans or 0,
            syn_retries=crec.keen_pbr_syn_retries or 0, failure=crec.failure == true,
            nocheck=crec.nocheck == true}
    end
    local function frame_for(d)
        local at = clock()
        if not integer(at, 0, 9007199254740991) then stop('clock_unavailable'); return end
        if at < last_at then stop('clock_changed'); return end
        last_at = at
        if at >= started + seconds then stop('expired'); return end
        if type(d) ~= 'table' or type(d.arg) ~= 'table' or type(d.track) ~= 'table'
            or type(d.track.lua_state) ~= 'table' or type(d.dis) ~= 'table'
            or type(d.dis.tcp) ~= 'table' then return end
        if (d.arg.key or d.func_instance) ~= pool then return end
        local ip, tcp = d.dis.ip or d.dis.ip6, d.dis.tcp
        if not ip then return end
        local src, dst = ip.ip_src or ip.ip6_src, ip.ip_dst or ip.ip6_dst
        if not src or not dst then return end
        local remote = ntop(d.outgoing and dst or src)
        local seen_client = ntop(d.outgoing and src or dst)
        local remote_port = d.outgoing and tcp.th_dport or tcp.th_sport
        local client_port = d.outgoing and tcp.th_sport or tcp.th_dport
        local endpoint = remote .. '|' .. tostring(remote_port)
        if not targets[endpoint] then return end
        local key = d.track.lua_state
        local meta = connections[key]
        -- Some incoming hooks see a pre-DNAT destination. Only a previously
        -- matched exact conntrack can admit such a reply; never broaden IP filters.
        if seen_client ~= client and not (not d.outgoing and meta and meta.endpoint == endpoint) then return end
        if not meta then
            if session.connection_count >= max_connections then stop('connection_limit'); return end
            session.connection_count = session.connection_count + 1
            meta = {id=session.connection_count, endpoint=endpoint, client_port=client_port}
            connections[key] = meta
        end
        local position
        if type(pos_get) == 'function' then position = pos_get(d, 's') end
        return {desync=d, meta=meta, row={time=at, connection=meta.id, client=client,
            client_port=meta.client_port, remote=remote, remote_port=remote_port, pool=pool,
            key_function=d.arg.hostkey or 'standard_hostkey', direction=d.outgoing and 'out' or 'in',
            payload_type=d.l7payload, sequence=position, flags=tcp.th_flags,
            payload_bytes=type(d.dis.payload) == 'string' and #d.dis.payload or 0,
            failure_detector=d.arg.failure_detector or 'standard_failure_detector',
            success_detector=d.arg.success_detector or 'standard_success_detector', check='not_checked'},
            maxtime=tonumber(d.arg.time) or 60}
    end
    wrappers.automate_host_record = function(d)
        local hrec = originals.automate_host_record(d)
        if current and current.desync == d then
            observe(function()
                if type(hrec) == 'table' then
                    current.hrec = hrec
                    current.row.slot_before = hrec.nstrategy
                end
            end)
        end
        return hrec
    end
    wrappers.automate_failure_check = function(d, hrec, crec)
        local frame = current and current.desync == d and current or nil
        local before = frame and observe(snapshot, hrec, crec)
        local result = originals.automate_failure_check(d, hrec, crec)
        if before then observe(function()
            local after, row = snapshot(hrec, crec), frame.row
            row.failures_before, row.failures_after = before.failures, after.failures
            row.retrans_before, row.retrans_after = before.retrans, after.retrans
            row.nocheck_before, row.nocheck_after = before.nocheck, after.nocheck
            row.check = 'pending'
            if before.nocheck then row.check = 'already_finished'
            elseif after.nocheck and after.failure then
                row.check = 'failure'
                row.counter_expired = type(before.failure_time) == 'number'
                    and row.time > before.failure_time + frame.maxtime
            elseif after.nocheck then row.check = 'success' end
            if after.syn_retries > before.syn_retries then row.reason = 'syn_retries'
            elseif after.retrans > before.retrans then row.reason = 'tcp_retransmissions'
            elseif row.check == 'failure' and not d.outgoing and bitand(d.dis.tcp.th_flags or 0, 4) ~= 0 then
                row.reason = 'incoming_rst'
            elseif row.check == 'failure' then row.reason = 'configured_detector'
            elseif row.check == 'success' then row.reason = 'configured_success_detector'
            elseif row.check == 'already_finished' then row.reason = 'nocheck' end
        end) end
        return result
    end
    local function finish_frame(frame, upstream_ok)
        local row, meta = frame.row, frame.meta
        if frame.hrec then
            row.slot_after, row.slot_count = frame.hrec.nstrategy, frame.hrec.ctstrategy
        end
        if not integer(row.slot_after, 1, 4096) then row.slot_after = nil end
        row.previous_selected = meta.last_selected
        if not meta.first_selected then meta.first_selected = row.slot_after end
        row.first_selected = meta.first_selected
        meta.last_selected = row.slot_after
        if not upstream_ok then row.check, row.reason = 'upstream_error', 'upstream_error' end
        session.events = session.events + 1
        -- Only scalar copies reach the sink, never desync, payload or state tables.
        local exported = {}
        for _, key in ipairs(fields) do
            local value = row[key]
            if type(value) == 'string' or type(value) == 'number' or type(value) == 'boolean' then
                exported[key] = value
            end
        end
        local sent = pcall(emit, exported)
        if not sent then stop('sink_error')
        elseif session.events >= max_events then stop('event_limit') end
    end
    wrappers.circular = function(ctx, d)
        local frame = observe(frame_for, d)
        if not frame then return originals.circular(ctx, d) end
        local parent = current
        current = frame
        local result = pack(pcall(originals.circular, ctx, d))
        current = parent
        observe(finish_frame, frame, result[1])
        if not result[1] then error(result[2], 0) end
        return unpack_values(result, 2, result.n)
    end
    for name, wrapped in pairs(wrappers) do _G[name] = wrapped end
    return {
        stop=function() stop('stopped') end,
        status=function() return {active=session.active, reason=session.reason,
            events=session.events, connections=session.connection_count, started=started,
            deadline=started + seconds} end,
    }
end
keen_pbr_rotator_trace = api
return api
