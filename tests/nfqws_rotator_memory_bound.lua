-- Exercise the shipped companion without creating files or advancing a timer
-- to perform eviction. In particular, the RAM cap must outlive that timer.
local companion = assert(loadfile(assert(arg[1], "companion path required")))
local now = 2000000000
local fail_telemetry, timer_deleted = false, false
local aggregate_writes, persistent_writes = 0, 0
local slot = 1

os.time = function() return now end
os.getenv = function(name)
    return name == "WRITABLE" and "/fixture/runtime" or "/fixture/learned"
end
os.remove = function() return true end
io.open = function(path, mode)
    if mode == "w" then
        if string.find(path, "rotator-state", 1, true) then
            if fail_telemetry then return nil, "injected telemetry write failure" end
            aggregate_writes = aggregate_writes + 1
        else
            persistent_writes = persistent_writes + 1
        end
    end
    return {
        read = function()
            if path == "/proc/self/stat" then
                return "111 (nfqws2) S 4 5 6 7 8 9 10 11 12 13 14 15 " ..
                    "16 17 18 19 20 21 222 23 24"
            end
            return ""
        end,
        write = function() return true end,
        flush = function() return true end,
        close = function() return true end,
    }
end
DLOG_ERR = function() end
timer_set = function() end
timer_del = function() timer_deleted = true end
automate_host_record = function() return {nstrategy = slot} end
standard_hostkey = function(desync) return desync.host end
standard_success_detector = function() return true end
companion()

-- Inspect only this test process's private learned table; no test hook or API
-- is exposed by the production companion.
local function learned_table()
    local visited = {}
    local function find(fn)
        if visited[fn] then return nil end
        visited[fn] = true
        local index = 1
        while true do
            local name, value = debug.getupvalue(fn, index)
            if not name then return nil end
            if name == "learned" then return value end
            if type(value) == "function" then
                local found = find(value)
                if found then return found end
            end
            index = index + 1
        end
    end
    return assert(find(standard_success_detector), "learned state not found")
end

local function check_bound(expected)
    local count = 0
    for _, revisions in pairs(learned_table()) do
        assert(next(revisions), "empty pool retained after eviction")
        for _, hosts in pairs(revisions) do
            assert(next(hosts), "empty revision retained after eviction")
            for _ in pairs(hosts) do count = count + 1 end
        end
    end
    assert(count <= 64, "live learned state exceeded 64 records: " .. count)
    if expected then assert(count == expected, "unexpected live record count") end
end

local revision = "0123456789abcdef"
local function succeed(host, pool, rev)
    standard_success_detector({
        host = host,
        arg = {key = pool or "yt_tcp", kpbr_rev = rev or revision},
        plan = {{arg = {strategy = "1"}}, {arg = {strategy = "2"}}},
    }, {})
    check_bound()
end

for index = 1, 200 do succeed(string.format("host%03d.example", index)) end
check_bound(64)
assert(learned_table().yt_tcp[revision]["host001.example"])
assert(learned_table().yt_tcp[revision]["host064.example"])
assert(not learned_table().yt_tcp[revision]["host065.example"])
assert(persistent_writes == 0, "RAM eviction caused a disk write")

-- Updating an existing key neither grows the table nor evicts a peer.
slot = 2
succeed("host001.example")
check_bound(64)
assert(learned_table().yt_tcp[revision]["host001.example"].slot == 2)

-- Newer successes evict old hosts, including empty pool/revision containers.
for index = 1, 100 do
    now = now + 1
    succeed("recent.example", "gv_tcp", string.format("%016x", index))
end
check_bound(64)
assert(not learned_table().yt_tcp, "retired pool retained")
assert(not learned_table().gv_tcp[string.format("%016x", 36)])
assert(learned_table().gv_tcp[string.format("%016x", 37)])

-- A full/unwritable telemetry directory stops the existing timer. Learning
-- remains advisory but bounded even without another maintenance callback.
fail_telemetry = true
keen_pbr_rotator_telemetry_timer()
assert(timer_deleted, "telemetry failure did not stop its timer")
for index = 1, 200 do
    now = now + 1
    succeed(string.format("after%03d.example", index), "yt_quic")
end
check_bound(64)
assert(not learned_table().gv_tcp, "evicted revisions retained")
assert(learned_table().yt_quic[revision]["after200.example"])
assert(aggregate_writes == 1, "unexpected aggregate publication")
assert(persistent_writes == 0, "telemetry failure caused persistence writes")
print("nfqws rotator live memory bound passed (before debounce and after timer failure)")
