local companion = assert(arg[1], "companion path is required")
local writable = assert(os.getenv("WRITABLE"), "WRITABLE is required")

local timer_callback = nil
local timer_deleted = false
local logged_error = nil
local generation_pid = 111
local generation_start_ticks = 222
local real_open = io.open

io.open = function(path, mode)
    if path == "/proc/self/stat" then
        local line = string.format(
            "%d (nfqws2) S 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 " ..
            "19 20 21 %d 23 24",
            generation_pid,
            generation_start_ticks)
        return {
            read = function(_, format)
                assert(format == "*l")
                return line
            end,
            close = function()
                return true
            end,
        }
    end
    return real_open(path, mode)
end

function DLOG_ERR(message)
    logged_error = message
end

function timer_set(name, callback, period, oneshot, data)
    assert(name == "keen_pbr_rotator_telemetry")
    assert(period == 10000)
    assert(oneshot == false)
    assert(data == nil)
    if type(callback) == "string" then
        timer_callback = assert(_G[callback], "timer callback is unavailable")
    else
        timer_callback = assert(callback)
    end
end

function timer_del(name)
    assert(name == "keen_pbr_rotator_telemetry")
    timer_deleted = true
end

autostate = {
    main_tcp = {
        ["secret.example"] = {
            nstrategy = 2,
            ctstrategy = 4,
            failure_counter = 1,
        },
        ["host-two"] = {
            nstrategy = 2,
            ctstrategy = 4,
        },
        ["host-three"] = {
            nstrategy = 3,
            ctstrategy = 4,
            failure_counter = 1,
        },
    },
    yt_quic = {
        ["video.example"] = {
            nstrategy = 1,
            ctstrategy = 2,
            failure_counter = 0,
        },
    },
}

for _, slot in ipairs({0, 1}) do
    local stale = assert(real_open(
        writable .. "/rotator-state." .. slot, "wb"))
    assert(stale:write("stale generation\n"))
    assert(stale:close())
end

assert(loadfile(companion), "companion has a syntax error")
dofile(companion)
assert(type(timer_callback) == "function", "periodic timer was not installed")

local function read_file(path)
    local handle = assert(io.open(path, "rb"))
    local content = assert(handle:read("*a"))
    assert(handle:close())
    return content
end

local first = read_file(writable .. "/rotator-state.1")
assert(string.match(first, "^V1\t1\t111\t222\t%d+\t0\n"))
assert(not real_open(writable .. "/rotator-state.0", "rb"),
    "the stale alternate buffer survived setup")
assert(string.find(
    first,
    "P\t6d61696e5f746370\t3\t2=2,3=1\t4=3\t0=1,1=2\n",
    1,
    true))
assert(string.find(
    first,
    "P\t79745f71756963\t1\t1=1\t2=1\t0=1\n",
    1,
    true))
assert(string.match(first, "END\t1\t2\t4\n$"))
assert(not string.find(first, "secret.example", 1, true))

autostate.main_tcp["host-three"].nstrategy = 4
generation_pid = 333
generation_start_ticks = 444
timer_callback("keen_pbr_rotator_telemetry", nil)
local second = read_file(writable .. "/rotator-state.0")
assert(string.match(second, "^V1\t2\t333\t444\t%d+\t0\n"))
assert(string.find(second, "\t2=2,4=1\t4=3\t", 1, true))
assert(string.match(first, "^V1\t1\t"), "the other buffer was overwritten")

autostate.invalid_pool = "not a host table"
autostate.main_tcp["malformed-host"] = "not a host record"
autostate.yt_quic["invalid-slot"] = {
    nstrategy = 3,
    ctstrategy = 2,
}
timer_callback("keen_pbr_rotator_telemetry", nil)
local partial = read_file(writable .. "/rotator-state.1")
assert(string.match(partial, "^V1\t3\t%d+\t%d+\t%d+\t1\n"))

local original_open = io.open
io.open = function(path, mode)
    if string.find(path, "rotator-state.", 1, true) then
        return nil, "injected snapshot failure"
    end
    return original_open(path, mode)
end
local survived, callback_error = pcall(
    timer_callback, "keen_pbr_rotator_telemetry", nil)
io.open = original_open
assert(survived, callback_error)
assert(timer_deleted, "a failed reporter did not remove its timer")
assert(string.find(
    logged_error or "", "injected snapshot failure", 1, true))

print("nfqws rotator telemetry Lua smoke passed")
