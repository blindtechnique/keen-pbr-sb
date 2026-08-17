-- Read-only telemetry bridge for zapret2 circular() state.
--
-- zapret-auto.lua keeps the authoritative state in
-- autostate[pool_key][host_key].  This companion never changes that table and
-- never changes hostkey selection.  It periodically publishes bounded,
-- aggregate histograms to WRITABLE so keen-pbr can expose them through its API.
--
-- Snapshot format (tab-separated, double buffered):
--   V1  sequence  pid  process_start_ticks  observed_unix  truncated
--   P   hex(pool_key) tracked slot_hist slot_count_hist pending_failure_hist
--   END sequence pool_count tracked_total
--
-- Histograms are comma-separated integer=count pairs.  Host keys are never
-- written, which keeps the snapshot small and avoids disclosing destinations.

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

local state = {
    disabled = false,
    directory = nil,
    sequence = 0,
}

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
    end
end

local function setup()
    if type(timer_set) ~= "function" then
        log_error("timer_set is unavailable; telemetry disabled")
        return
    end
    if type(io) ~= "table" or type(io.open) ~= "function" then
        log_error("file I/O is unavailable; telemetry disabled")
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

local initialized, initialization_error = pcall(setup)
if not initialized then
    disable_telemetry(initialization_error)
end
