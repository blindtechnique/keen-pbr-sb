-- Telemetry and bounded learned-selection companion for zapret2 circular().
--
-- zapret-auto.lua keeps the authoritative state in
-- autostate[pool_key][host_key].  For explicitly revisioned YouTube pools this
-- companion can lazily seed only hrec.nstrategy from a previously confirmed
-- stock success.  It never changes hostkey selection, ctstrategy, or failure
-- counters.  It also periodically publishes bounded aggregate histograms to
-- WRITABLE so keen-pbr can expose them through its API.
--
-- Snapshot format (tab-separated, double buffered):
--   V1  sequence  pid  process_start_ticks  observed_unix  truncated
--   P   hex(pool_key) tracked slot_hist slot_count_hist pending_failure_hist
--   END sequence pool_count tracked_total
--
-- Histograms are comma-separated integer=count pairs.  Aggregate snapshots do
-- not contain host keys.  The separate bounded learned-state files contain
-- encoded host keys plus only their confirmed slot, slot count, and revision.

local SNAPSHOT_PERIOD_MS = 10000
local MAX_POOLS = 64
-- This also caps the worst-case serialized histogram below the backend's
-- 128 KiB read limit, even if every target occupies a distinct bucket in all
-- three histograms.
-- zapret-auto retains host records for the process lifetime. Keep this equal
-- to the backend's bounded aggregate limit so a busy office does not become
-- permanently partial earlier than the reader contract requires.
local MAX_TARGETS = 4096
local MAX_POOL_KEY_BYTES = 128
local MAX_SLOT = 4096
local MAX_PENDING_FAILURES = 65535
local TIMER_NAME = "keen_pbr_rotator_telemetry"

-- Learned selections are advisory.  They never block nfqws2 startup and are
-- deliberately much narrower than live telemetry: only the three dedicated
-- YouTube pools participate.  The two fixed files are pre-created by the
-- package so the unprivileged nfqws2 process never needs write access to their
-- parent directory.  Tests may redirect the prefix to a temporary directory.
local PERSISTENT_PREFIX = os.getenv(
    "KEEN_PBR_NFQWS_ROTATOR_LEARNED_PREFIX")
    or "/opt/var/lib/keen-pbr/nfqws-rotator-learned-v1"
local PERSISTENT_MAGIC = "KPRS1"
local PERSISTENT_MAX_BYTES = 128 * 1024
local PERSISTENT_MAX_RECORDS = 64
local PERSISTENT_MAX_HOST_KEY_BYTES = 253
local PERSISTENT_REVISION_BYTES = 16
local PERSISTENT_EXPIRY_SECONDS = 30 * 24 * 60 * 60
local PERSISTENT_DIRTY_DEBOUNCE_SECONDS = 120
local PERSISTENT_WRITE_INTERVAL_SECONDS = 6 * 60 * 60
local PERSISTENT_SAME_SLOT_REFRESH_SECONDS = 7 * 24 * 60 * 60
local PERSISTENT_FUTURE_SKEW_SECONDS = 300
-- Keenetic may start nfqws2 before NTP with a small Unix timestamp.  A broad
-- 2020 floor distinguishes that boot clock without requiring another worker.
local PERSISTENT_MIN_CREDIBLE_UNIX = 1577836800
local ELIGIBLE_PERSISTENT_POOLS = {
    gv_tcp = true,
    yt_tcp = true,
    yt_quic = true,
}

local state = {
    disabled = false,
    directory = nil,
    sequence = 0,
    persistent_disabled = false,
    persistent_sequence = 0,
    persistent_last_write_unix = nil,
    persistent_first_dirty_unix = nil,
    persistent_time_ready = false,
}

-- learned[pool_key][revision][host_key] = {
--     slot = N, slot_count = N, confirmed_at = unix_time
-- }
-- Only a success reported by stock standard_success_detector() enters this
-- table.  In particular, failure counters and an unproven rotated slot are
-- never durable.
local learned = {}
local pending_persistent_snapshot = nil

local function log_error(message)
    if type(DLOG_ERR) == "function" then
        pcall(DLOG_ERR, "keen-pbr rotator telemetry: " .. tostring(message))
    end
end

local function integer_in_range(value, minimum, maximum)
    return type(value) == "number"
        and value == math.floor(value)
        and value >= minimum
        and value <= maximum
end

local function disable_persistence(message)
    if state.persistent_disabled then
        return
    end
    state.persistent_disabled = true
    if message then
        log_error("learned-state disabled: " .. tostring(message))
    end
end

local function split_exact(value, delimiter)
    local result = {}
    local start = 1
    while true do
        local found = string.find(value, delimiter, start, true)
        if not found then
            result[#result + 1] = string.sub(value, start)
            return result
        end
        result[#result + 1] = string.sub(value, start, found - 1)
        start = found + #delimiter
    end
end

local function parse_decimal(value, minimum, maximum)
    if type(value) ~= "string" or not string.match(value, "^%d+$") then
        return nil
    end
    local parsed = tonumber(value)
    if not integer_in_range(parsed, minimum, maximum) then
        return nil
    end
    return parsed
end

local function valid_revision(value)
    return type(value) == "string"
        and #value == PERSISTENT_REVISION_BYTES
        and string.match(value, "^[0-9a-f]+$") ~= nil
end

local function valid_host_key(value)
    if type(value) ~= "string"
        or #value == 0
        or #value > PERSISTENT_MAX_HOST_KEY_BYTES then
        return false
    end
    for index = 1, #value do
        local byte = string.byte(value, index)
        if byte < 0x21 or byte > 0x7e then
            return false
        end
    end
    return true
end

local function hex_decode(value, maximum_bytes)
    if type(value) ~= "string"
        or #value == 0
        or (#value % 2) ~= 0
        or #value > maximum_bytes * 2
        or string.match(value, "^[0-9a-f]+$") == nil then
        return nil
    end
    local decoded = {}
    for index = 1, #value, 2 do
        decoded[#decoded + 1] = string.char(
            tonumber(string.sub(value, index, index + 1), 16))
    end
    return table.concat(decoded)
end

local function current_unix()
    local value = os.time()
    if not integer_in_range(value, 1, 9007199254740991) then
        return nil
    end
    return value
end

local function credible_unix()
    local value = current_unix()
    if not value or value < PERSISTENT_MIN_CREDIBLE_UNIX then
        return nil
    end
    return value
end

local function persistent_path(slot)
    return string.format("%s.%d", PERSISTENT_PREFIX, slot)
end

local function put_learned(entry)
    local by_revision = learned[entry.pool]
    if not by_revision then
        by_revision = {}
        learned[entry.pool] = by_revision
    end
    local by_host = by_revision[entry.revision]
    if not by_host then
        by_host = {}
        by_revision[entry.revision] = by_host
    end
    by_host[entry.host] = {
        slot = entry.slot,
        slot_count = entry.slot_count,
        confirmed_at = entry.confirmed_at,
    }
end

local function find_learned(pool, revision, host)
    local by_revision = learned[pool]
    local by_host = by_revision and by_revision[revision]
    return by_host and by_host[host] or nil
end

local function parse_persistent_snapshot(content)
    if type(content) ~= "string"
        or #content == 0
        or #content > PERSISTENT_MAX_BYTES
        or string.sub(content, -1) ~= "\n" then
        return nil
    end

    local lines = {}
    for line in string.gmatch(content, "([^\n]*)\n") do
        lines[#lines + 1] = line
    end
    if #lines < 2 then
        return nil
    end

    local header = split_exact(lines[1], "\t")
    if #header ~= 4 or header[1] ~= PERSISTENT_MAGIC then
        return nil
    end
    local sequence = parse_decimal(header[2], 0, 9007199254740991)
    local written_at = parse_decimal(header[3], 1, 9007199254740991)
    local declared_count =
        parse_decimal(header[4], 0, PERSISTENT_MAX_RECORDS)
    if not sequence or not written_at or not declared_count then
        return nil
    end

    local entries = {}
    local seen = {}
    local row_count = 0
    for index = 2, #lines - 1 do
        local fields = split_exact(lines[index], "\t")
        if #fields ~= 7 or fields[1] ~= "S" then
            return nil
        end
        local pool = hex_decode(fields[2], MAX_POOL_KEY_BYTES)
        local revision = fields[3]
        local host = hex_decode(fields[4], PERSISTENT_MAX_HOST_KEY_BYTES)
        local slot = parse_decimal(fields[5], 1, MAX_SLOT)
        local slot_count = parse_decimal(fields[6], 1, MAX_SLOT)
        local confirmed_at =
            parse_decimal(fields[7], 1, 9007199254740991)
        if not pool or not ELIGIBLE_PERSISTENT_POOLS[pool]
            or not valid_revision(revision)
            or not host or not valid_host_key(host)
            or not slot or not slot_count or slot > slot_count
            or not confirmed_at then
            return nil
        end
        row_count = row_count + 1
        local unique = pool .. "\0" .. revision .. "\0" .. host
        if seen[unique] then
            return nil
        end
        seen[unique] = true
        entries[#entries + 1] = {
            pool = pool,
            revision = revision,
            host = host,
            slot = slot,
            slot_count = slot_count,
            confirmed_at = confirmed_at,
        }
    end

    local ending = split_exact(lines[#lines], "\t")
    local end_sequence = #ending == 3
        and parse_decimal(ending[2], 0, 9007199254740991) or nil
    local end_count = #ending == 3
        and parse_decimal(ending[3], 0, PERSISTENT_MAX_RECORDS) or nil
    if #ending ~= 3 or ending[1] ~= "END"
        or end_sequence ~= sequence
        or end_count ~= declared_count
        or row_count ~= declared_count then
        return nil
    end
    return {
        sequence = sequence,
        written_at = written_at,
        entries = entries,
    }
end

local function read_persistent_slot(slot)
    local handle = io.open(persistent_path(slot), "rb")
    if not handle then
        return false, nil
    end
    local content = handle:read(PERSISTENT_MAX_BYTES + 1)
    handle:close()
    if type(content) ~= "string" or #content > PERSISTENT_MAX_BYTES then
        return true, nil
    end
    return true, parse_persistent_snapshot(content)
end

local function activate_persistent_time_if_ready()
    if state.persistent_disabled or state.persistent_time_ready then
        return state.persistent_time_ready
    end
    local now = credible_unix()
    if not now then
        return false
    end

    local selected = pending_persistent_snapshot
    if selected and selected.written_at
            > now + PERSISTENT_FUTURE_SKEW_SECONDS then
        return false
    end

    state.persistent_time_ready = true
    pending_persistent_snapshot = nil
    if selected then
        state.persistent_last_write_unix = selected.written_at
        learned = {}
        for _, entry in ipairs(selected.entries) do
            if entry.confirmed_at
                    <= now + PERSISTENT_FUTURE_SKEW_SECONDS
                and now <= entry.confirmed_at
                    + PERSISTENT_EXPIRY_SECONDS then
                put_learned(entry)
            end
        end
    end
    return true
end

local function load_persistent_state()
    if state.persistent_disabled then
        return
    end
    local zero_exists, zero = read_persistent_slot(0)
    local one_exists, one = read_persistent_slot(1)
    if not zero_exists or not one_exists then
        disable_persistence(nil)
        return
    end
    local selected = zero
    if one and (not selected or one.sequence > selected.sequence) then
        selected = one
    end
    if not selected then
        activate_persistent_time_if_ready()
        return
    end
    -- Preserve the highest structurally valid sequence even before NTP.  This
    -- prevents a pre-sync write from restarting at sequence 1 and leaving an
    -- older, numerically newer buffer to win on the next process start.
    state.persistent_sequence = selected.sequence
    pending_persistent_snapshot = selected
    -- Until the wall clock is trustworthy, exact revision and slot-count
    -- matches may use the structurally valid snapshot as an advisory seed.
    for _, entry in ipairs(selected.entries) do
        put_learned(entry)
    end
    activate_persistent_time_if_ready()
end

local function read_process_generation()
    local handle = io.open("/proc/self/stat", "r")
    if not handle then
        return nil, nil
    end
    local line = handle:read("*l")
    handle:close()
    if type(line) ~= "string" then
        return nil, nil
    end

    -- /proc/PID/stat uses "pid (comm) field3 ... field22".  %b() handles
    -- parentheses inside comm; after the closing parenthesis starttime is the
    -- twentieth whitespace-delimited field.
    local pid_text, rest = string.match(line, "^(%d+)%s+%b()%s+(.+)$")
    if not pid_text or not rest then
        return nil, nil
    end
    local fields = {}
    for field in string.gmatch(rest, "%S+") do
        fields[#fields + 1] = field
        if #fields >= 20 then
            break
        end
    end
    local pid = tonumber(pid_text)
    local start_ticks = tonumber(fields[20])
    if not integer_in_range(pid, 1, 2147483647)
        or not integer_in_range(start_ticks, 1, 9007199254740991) then
        return nil, nil
    end
    return pid, start_ticks
end

local function hex_encode(value)
    return (string.gsub(value, ".", function(character)
        return string.format("%02x", string.byte(character))
    end))
end

local function valid_pool_key(value)
    if type(value) ~= "string"
        or #value == 0
        or #value > MAX_POOL_KEY_BYTES then
        return false
    end
    for index = 1, #value do
        local byte = string.byte(value, index)
        if byte < 0x21 or byte > 0x7e then
            return false
        end
    end
    return true
end

local function histogram_add(histogram, value)
    histogram[value] = (histogram[value] or 0) + 1
end

local function render_histogram(histogram)
    local keys = {}
    for value in pairs(histogram) do
        keys[#keys + 1] = value
    end
    table.sort(keys)
    local fields = {}
    for _, value in ipairs(keys) do
        fields[#fields + 1] = string.format(
            "%.0f=%.0f", value, histogram[value])
    end
    return table.concat(fields, ",")
end

local function plan_strategy_count(desync)
    if type(desync) ~= "table" or type(desync.plan) ~= "table" then
        return nil
    end
    local unique = {}
    local count = 0
    local maximum = 0
    for _, instance in pairs(desync.plan) do
        local value = type(instance) == "table"
            and type(instance.arg) == "table"
            and instance.arg.strategy or nil
        if value ~= nil then
            local slot = tonumber(value)
            if not integer_in_range(slot, 1, MAX_SLOT) then
                return nil
            end
            if not unique[slot] then
                unique[slot] = true
                count = count + 1
                if slot > maximum then
                    maximum = slot
                end
            end
        end
    end
    if count == 0 or count ~= maximum then
        return nil
    end
    return count
end

local function rotator_identity(desync)
    if type(desync) ~= "table" or type(desync.arg) ~= "table" then
        return nil
    end
    local pool = desync.arg.key
    if type(pool) ~= "string" or #pool == 0 then
        pool = desync.func_instance
    end
    local revision = desync.arg.kpbr_rev
    if not ELIGIBLE_PERSISTENT_POOLS[pool]
        or not valid_revision(revision) then
        return nil
    end

    local generator = standard_hostkey
    if desync.arg.hostkey ~= nil then
        generator = _G[desync.arg.hostkey]
    end
    if type(generator) ~= "function" then
        return nil
    end
    local ok, host = pcall(generator, desync)
    if not ok or not valid_host_key(host) then
        return nil
    end
    return pool, revision, host
end

local upstream_automate_host_record = nil
local upstream_standard_success_detector = nil

local function restore_learned_selection(desync, host_record)
    if type(host_record) ~= "table" or host_record.nstrategy ~= nil then
        return
    end
    local pool, revision, host = rotator_identity(desync)
    if not pool then
        return
    end
    local entry = find_learned(pool, revision, host)
    local slot_count = plan_strategy_count(desync)
    local now = credible_unix()
    if not entry or not slot_count
        or entry.slot_count ~= slot_count
        or not integer_in_range(entry.slot, 1, slot_count) then
        return
    end
    if state.persistent_time_ready
        and (not now
            or now > entry.confirmed_at + PERSISTENT_EXPIRY_SECONDS
            or entry.confirmed_at
                > now + PERSISTENT_FUTURE_SKEW_SECONDS) then
        return
    end
    host_record.nstrategy = entry.slot
end

local function mark_learned_success(desync)
    if state.persistent_disabled
        or not state.persistent_time_ready
        or not upstream_automate_host_record then
        return
    end
    local pool, revision, host = rotator_identity(desync)
    local slot_count = plan_strategy_count(desync)
    if not pool or not slot_count then
        return
    end
    local host_record = upstream_automate_host_record(desync)
    local slot = type(host_record) == "table" and host_record.nstrategy or nil
    if not integer_in_range(slot, 1, slot_count) then
        return
    end
    local now = credible_unix()
    if not now then
        return
    end

    local existing = find_learned(pool, revision, host)
    local changed = not existing
        or existing.slot ~= slot
        or existing.slot_count ~= slot_count
    local refresh = existing
        and now >= existing.confirmed_at
            + PERSISTENT_SAME_SLOT_REFRESH_SECONDS
    if not changed and not refresh then
        return
    end
    put_learned({
        pool = pool,
        revision = revision,
        host = host,
        slot = slot,
        slot_count = slot_count,
        confirmed_at = now,
    })
    if not state.persistent_first_dirty_unix then
        state.persistent_first_dirty_unix = now
    end
end

local function install_persistence_hooks()
    if type(automate_host_record) ~= "function"
        or type(standard_success_detector) ~= "function" then
        disable_persistence(nil)
        return
    end
    upstream_automate_host_record = automate_host_record
    upstream_standard_success_detector = standard_success_detector

    automate_host_record = function(desync)
        local host_record = upstream_automate_host_record(desync)
        pcall(restore_learned_selection, desync, host_record)
        return host_record
    end

    standard_success_detector = function(desync, connection_record)
        local succeeded =
            upstream_standard_success_detector(desync, connection_record)
        if succeeded then
            pcall(mark_learned_success, desync)
        end
        return succeeded
    end
end

local function collect_snapshot()
    local pools = {}
    local visited_pools = 0
    local visited_targets = 0
    local tracked_total = 0
    local truncated = false
    local stop = false

    if autostate ~= nil and type(autostate) ~= "table" then
        return pools, tracked_total, true
    end

    for pool_key, host_table in pairs(autostate or {}) do
        visited_pools = visited_pools + 1
        if visited_pools > MAX_POOLS then
            truncated = true
            break
        end

        if valid_pool_key(pool_key) and type(host_table) == "table" then
            local pool = {
                key = pool_key,
                tracked = 0,
                slots = {},
                slot_counts = {},
                failures = {},
            }
            for _, host_record in pairs(host_table) do
                visited_targets = visited_targets + 1
                if visited_targets > MAX_TARGETS then
                    truncated = true
                    stop = true
                    break
                end

                if type(host_record) == "table" then
                    local active_slot = host_record.nstrategy
                    local slot_count = host_record.ctstrategy
                    local pending_failures = host_record.failure_counter or 0
                    if integer_in_range(active_slot, 1, MAX_SLOT)
                        and integer_in_range(slot_count, 1, MAX_SLOT)
                        and active_slot <= slot_count
                        and integer_in_range(
                            pending_failures, 0, MAX_PENDING_FAILURES) then
                        histogram_add(pool.slots, active_slot)
                        histogram_add(pool.slot_counts, slot_count)
                        histogram_add(pool.failures, pending_failures)
                        pool.tracked = pool.tracked + 1
                        tracked_total = tracked_total + 1
                    else
                        truncated = true
                    end
                else
                    truncated = true
                end
            end
            if pool.tracked > 0 then
                pools[#pools + 1] = pool
            end
        else
            truncated = true
        end

        if stop then
            break
        end
    end

    table.sort(pools, function(left, right)
        return left.key < right.key
    end)
    return pools, tracked_total, truncated
end

local function write_checked(handle, text)
    local ok, error_message = handle:write(text)
    if not ok then
        error(error_message or "snapshot write failed")
    end
end

local function write_snapshot()
    -- nfqws2 initializes Lua before daemonizing. Re-read the generation for
    -- every publication so the first timer run after fork is fenced to the
    -- long-lived child rather than the short-lived parent.
    local pid, start_ticks = read_process_generation()
    if not pid or not start_ticks then
        error("cannot read /proc/self/stat")
    end
    local pools, tracked_total, truncated = collect_snapshot()
    state.sequence = state.sequence + 1
    local sequence = state.sequence
    local path = string.format(
        "%s/rotator-state.%d", state.directory, sequence % 2)
    local handle, open_error = io.open(path, "w")
    if not handle then
        error(open_error or "cannot open snapshot")
    end

    local ok, write_error = pcall(function()
        write_checked(handle, string.format(
            "V1\t%.0f\t%.0f\t%.0f\t%.0f\t%d\n",
            sequence,
            pid,
            start_ticks,
            os.time(),
            truncated and 1 or 0))
        for _, pool in ipairs(pools) do
            write_checked(handle, string.format(
                "P\t%s\t%.0f\t%s\t%s\t%s\n",
                hex_encode(pool.key),
                pool.tracked,
                render_histogram(pool.slots),
                render_histogram(pool.slot_counts),
                render_histogram(pool.failures)))
        end
        write_checked(handle, string.format(
            "END\t%.0f\t%.0f\t%.0f\n",
            sequence,
            #pools,
            tracked_total))
        local flushed, flush_error = handle:flush()
        if not flushed then
            error(flush_error or "snapshot flush failed")
        end
    end)
    local closed, close_error = handle:close()
    if not ok then
        error(write_error)
    end
    if not closed then
        error(close_error or "snapshot close failed")
    end
end

local function collect_persistent_entries(now)
    local entries = {}
    for pool, by_revision in pairs(learned) do
        if ELIGIBLE_PERSISTENT_POOLS[pool]
            and type(by_revision) == "table" then
            for revision, by_host in pairs(by_revision) do
                if valid_revision(revision) and type(by_host) == "table" then
                    for host, entry in pairs(by_host) do
                        if valid_host_key(host)
                            and type(entry) == "table"
                            and integer_in_range(entry.slot, 1, MAX_SLOT)
                            and integer_in_range(
                                entry.slot_count, 1, MAX_SLOT)
                            and entry.slot <= entry.slot_count
                            and integer_in_range(
                                entry.confirmed_at, 1, 9007199254740991)
                            and now <= entry.confirmed_at
                                + PERSISTENT_EXPIRY_SECONDS then
                            entries[#entries + 1] = {
                                pool = pool,
                                revision = revision,
                                host = host,
                                slot = entry.slot,
                                slot_count = entry.slot_count,
                                confirmed_at = entry.confirmed_at,
                            }
                        end
                    end
                end
            end
        end
    end

    -- Keep the most recently confirmed records if the fixed bound is reached.
    table.sort(entries, function(left, right)
        if left.confirmed_at ~= right.confirmed_at then
            return left.confirmed_at > right.confirmed_at
        end
        if left.pool ~= right.pool then
            return left.pool < right.pool
        end
        if left.revision ~= right.revision then
            return left.revision < right.revision
        end
        return left.host < right.host
    end)
    while #entries > PERSISTENT_MAX_RECORDS do
        table.remove(entries)
    end

    -- Stable ordering prevents logically identical batches from producing
    -- different bytes.
    table.sort(entries, function(left, right)
        if left.pool ~= right.pool then
            return left.pool < right.pool
        end
        if left.revision ~= right.revision then
            return left.revision < right.revision
        end
        return left.host < right.host
    end)
    return entries
end

local function replace_learned(entries)
    learned = {}
    for _, entry in ipairs(entries) do
        put_learned(entry)
    end
end

local function render_persistent_snapshot(sequence, now, entries)
    local lines = {
        string.format(
            "%s\t%.0f\t%.0f\t%d",
            PERSISTENT_MAGIC, sequence, now, #entries),
    }
    for _, entry in ipairs(entries) do
        lines[#lines + 1] = string.format(
            "S\t%s\t%s\t%s\t%.0f\t%.0f\t%.0f",
            hex_encode(entry.pool),
            entry.revision,
            hex_encode(entry.host),
            entry.slot,
            entry.slot_count,
            entry.confirmed_at)
    end
    lines[#lines + 1] =
        string.format("END\t%.0f\t%d", sequence, #entries)
    return table.concat(lines, "\n") .. "\n"
end

local function write_persistent_if_due()
    if state.persistent_disabled
        or not state.persistent_time_ready
        or not state.persistent_first_dirty_unix then
        return
    end
    local now = credible_unix()
    if not now then
        return
    end
    if now < state.persistent_first_dirty_unix then
        state.persistent_first_dirty_unix = now
        return
    end
    if now - state.persistent_first_dirty_unix
        < PERSISTENT_DIRTY_DEBOUNCE_SECONDS then
        return
    end
    if state.persistent_last_write_unix
        and now < state.persistent_last_write_unix
            + PERSISTENT_WRITE_INTERVAL_SECONDS then
        return
    end

    local sequence = state.persistent_sequence + 1
    if sequence > 9007199254740991 then
        sequence = 1
    end
    local entries = collect_persistent_entries(now)
    local path = persistent_path(sequence % 2)

    -- The package pre-creates both leaves. Refuse to create a new path: the
    -- parent remains non-writable to the nfqws2 user by design.
    local existing = io.open(path, "rb")
    if not existing then
        error("learned-state slot is unavailable")
    end
    existing:close()

    local handle, open_error = io.open(path, "w")
    if not handle then
        error(open_error or "cannot open learned-state slot")
    end
    local ok, write_error = pcall(function()
        write_checked(
            handle,
            render_persistent_snapshot(sequence, now, entries))
        local flushed, flush_error = handle:flush()
        if not flushed then
            error(flush_error or "learned-state flush failed")
        end
    end)
    local closed, close_error = handle:close()
    if not ok then
        error(write_error)
    end
    if not closed then
        error(close_error or "learned-state close failed")
    end

    state.persistent_sequence = sequence
    state.persistent_last_write_unix = now
    state.persistent_first_dirty_unix = nil
    replace_learned(entries)
end

local function disable_telemetry(message)
    if state.disabled then
        return
    end
    state.disabled = true
    log_error(message)
    if type(timer_del) == "function" then
        pcall(timer_del, TIMER_NAME)
    end
end

function keen_pbr_rotator_telemetry_timer()
    if state.disabled then
        return
    end
    local ok, error_message = pcall(write_snapshot)
    if not ok then
        disable_telemetry(error_message)
        return
    end
    if not state.persistent_disabled then
        local persisted, persistence_error = pcall(function()
            activate_persistent_time_if_ready()
            write_persistent_if_due()
        end)
        if not persisted then
            disable_persistence(persistence_error)
        end
    end
end

local function setup()
    if type(io) ~= "table" or type(io.open) ~= "function" then
        log_error("file I/O is unavailable; telemetry disabled")
        return
    end
    load_persistent_state()
    if type(timer_set) ~= "function" then
        log_error("timer_set is unavailable; telemetry disabled")
        return
    end
    state.directory = os.getenv("WRITABLE")
    if type(state.directory) ~= "string" or #state.directory == 0 then
        log_error("WRITABLE is unavailable; telemetry disabled")
        return
    end

    -- --writable may have been reassigned to a different USER since the last
    -- service start. The new owner can safely unlink fixed leaves from its own
    -- directory even when their previous inode owner can no longer write them.
    for _, slot in ipairs({0, 1}) do
        pcall(os.remove, string.format(
            "%s/rotator-state.%d", state.directory, slot))
    end

    -- Publish a current-generation snapshot immediately. The backend fences
    -- this pre-daemon snapshot by PID/startticks until the child timer writes.
    local written, write_error = pcall(write_snapshot)
    if not written then
        disable_telemetry(write_error)
        return
    end
    timer_set(
        TIMER_NAME,
        "keen_pbr_rotator_telemetry_timer",
        SNAPSHOT_PERIOD_MS,
        false,
        nil)
end

local hooks_installed, hooks_error = pcall(install_persistence_hooks)
if not hooks_installed then
    disable_persistence(hooks_error)
end

local initialized, initialization_error = pcall(setup)
if not initialized then
    disable_telemetry(initialization_error)
end
