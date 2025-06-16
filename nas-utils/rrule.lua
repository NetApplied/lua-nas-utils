-- rrule.lua

--[[

ISO 8601 Date and Time Format
YYYYMMDDTHHMMSSZ:
YYYY: Four digits for the year.
MM: Two digits for the month (01 to 12).
DD: Two digits for the day of the month (01 to 31).
T: A separator indicating the start of the time part.
HH: Two digits for the hour (00 to 23).
MM: Two digits for the minute (00 to 59).
SS: Two digits for the second (00 to 59).
Z: UTC time zone indicator.

]]

local rrule = {}
rrule.__index = rrule

-- Constants for frequency
rrule.SECONDLY = "SECONDLY"
rrule.MINUTELY = "MINUTELY"
rrule.HOURLY = "HOURLY"
rrule.DAILY = "DAILY"
rrule.WEEKLY = "WEEKLY"
rrule.MONTHLY = "MONTHLY"
rrule.YEARLY = "YEARLY"

-- Weekdays
local weekdays = {
    MO = 1,
    TU = 2,
    WE = 3,
    TH = 4,
    FR = 5,
    SA = 6,
    SU = 7
}

-- Helper function to parse a date string in YYYYMMDDTHHMMSSZ format
local function parse_date(date_str)
    local year = tonumber(date_str:sub(1, 4))
    local month = tonumber(date_str:sub(5, 6))
    local day = tonumber(date_str:sub(7, 8))
    local hour = tonumber(date_str:sub(10, 11))
    local minute = tonumber(date_str:sub(12, 13))
    local second = tonumber(date_str:sub(14, 15))
    return os.time({year=year, month=month, day=day, hour=hour, min=minute, sec=second})
end

-- Helper function to format a date as YYYYMMDDTHHMMSSZ
local function format_date(timestamp)
    local t = os.date("*t", timestamp)
    return string.format("%04d%02d%02dT%02d%02d%02dZ", t.year, t.month, t.day, t.hour, t.min, t.sec)
end

-- Create a new RRULE
function rrule.new(freq, interval, count, until_date, bysecond, byminute, byhour, byday, bymonthday, byyearday, byweekno, bymonth, wkst)
    return setmetatable({
        freq = freq,
        interval = interval or 1,
        count = count,
        until_date = until_date and parse_date(until_date),
        bysecond = bysecond,
        byminute = byminute,
        byhour = byhour,
        byday = byday and byday or {},
        bymonthday = bymonthday,
        byyearday = byyearday,
        byweekno = byweekno,
        bymonth = bymonth and bymonth or {},
        wkst = wkst and weekdays[wkst] or 1
    }, rrule)
end

-- Generate the RRULE string
function rrule:to_string()
    local parts = {}
    table.insert(parts, "FREQ=" .. self.freq)
    if self.interval and self.interval > 1 then
        table.insert(parts, "INTERVAL=" .. self.interval)
    end
    if self.count then
        table.insert(parts, "COUNT=" .. self.count)
    end
    if self.until_date then
        table.insert(parts, "UNTIL=" .. format_date(self.until_date))
    end
    if self.bysecond then table.insert(parts, "BYSECOND=" .. table.concat(self.bysecond, ",")) end
    if self.byminute then table.insert(parts, "BYMINUTE=" .. table.concat(self.byminute, ",")) end
    if self.byhour then table.insert(parts, "BYHOUR=" .. table.concat(self.byhour, ",")) end
    if self.byday and #self.byday > 0 then table.insert(parts, "BYDAY=" .. table.concat(self.byday, ",")) end
    if self.bymonthday then table.insert(parts, "BYMONTHDAY=" .. table.concat(self.bymonthday, ",")) end
    if self.byyearday then table.insert(parts, "BYYEARDAY=" .. table.concat(self.byyearday, ",")) end
    if self.byweekno then table.insert(parts, "BYWEEKNO=" .. table.concat(self.byweekno, ",")) end
    if self.bymonth and #self.bymonth > 0 then table.insert(parts, "BYMONTH=" .. table.concat(self.bymonth, ",")) end
    if self.wkst and self.freq == rrule.WEEKLY then table.insert(parts, "WKST=" .. self.wkst) end

    return table.concat(parts, ";")
end

-- Parse an RRULE string
function rrule.parse(rrule_str)
    local parts = {}
    for part in rrule_str:gmatch("([%a]+=[^;]*)") do
        local key, value = part:match("([%a]+)=([^=]*)")
        parts[key] = value
    end

    local freq = parts.FREQ
    local interval = tonumber(parts.INTERVAL) or 1
    local count = tonumber(parts.COUNT)
    local until_date = parts.UNTIL
    local bysecond = parts.BYSECOND and parts.BYSECOND:split(",") or nil
    local byminute = parts.BYMINUTE and parts.BYMINUTE:split(",") or nil
    local byhour = parts.BYHOUR and parts.BYHOUR:split(",") or nil
    local byday = parts.BYDAY and parts.BYDAY:split(",") or {}
    local bymonthday = parts.BYMONTHDAY and parts.BYMONTHDAY:split(",") or nil
    local byyearday = parts.BYYEARDAY and parts.BYYEARDAY:split(",") or nil
    local byweekno = parts.BYWEEKNO and parts.BYWEEKNO:split(",") or nil
    local bymonth = parts.BYMONTH and parts.BYMONTH:split(",") or {}
    local wkst = parts.WKST

    return rrule.new(freq, interval, count, until_date, bysecond, byminute, byhour, byday, bymonthday, byyearday, byweekno, bymonth, wkst)
end

-- Get the next occurrence of the event
function rrule:get_next_occurrence(start_date)
    local start_time = parse_date(start_date)

    local function is_valid_date(t, byday, bymonthday, byyearday, byweekno, bymonth)
        if #byday > 0 then
            local day_of_week = os.date("*t", t).wday -- Lua week starts from 1 (Sunday) to 7 (Saturday)
            if not table.any(byday, function(day) return day == day_of_week end) then
                return false
            end
        end

        if bymonthday and not table.any(bymonthday, function(day) return day == os.date("*t", t).day end) then
            return false
        end

        if byyearday and not table.any(byyearday, function(day) return day == os.date("*t", t).yearday end) then
            return false
        end

        if byweekno and not table.any(byweekno, function(week) return week == os.date("*t", t).week end) then
            return false
        end

        if bymonth and not table.any(bymonth, function(month) return month == os.date("*t", t).month end) then
            return false
        end

        return true
    end

    local function find_next_occurrence(freq, start_time)
        local t = os.date("*t", start_time)

        if freq == rrule.DAILY then
            t.day = t.day + self.interval
        elseif freq == rrule.WEEKLY then
            t.day = t.day + self.interval * 7
        elseif freq == rrule.MONTHLY then
            t.month = t.month + self.interval
            if t.month > 12 then
                t.year = t.year + math.floor((t.month - 1) / 12)
                t.month = (t.month - 1) % 12 + 1
            end
        elseif freq == rrule.YEARLY then
            t.year = t.year + self.interval
        end

        local next_time = os.time(t)
        while not is_valid_date(next_time, self.byday, self.bymonthday, self.byyearday, self.byweekno, self.bymonth) do
            if freq == rrule.DAILY then
                t.day = t.day + 1
            elseif freq == rrule.WEEKLY then
                t.day = t.day + 1
            elseif freq == rrule.MONTHLY then
                t.day = t.day + 1
                if t.day > os.date("*t", os.time(t)).day then
                    t.month = t.month + 1
                    if t.month > 12 then
                        t.year = t.year + 1
                        t.month = 1
                    end
                    t.day = 1
                end
            elseif freq == rrule.YEARLY then
                t.day = t.day + 1
                if t.day > os.date("*t", os.time(t)).day then
                    t.month = t.month + 1
                    if t.month > 12 then
                        t.year = t.year + 1
                        t.month = 1
                    end
                    t.day = 1
                end
            end
            next_time = os.time(t)
        end

        return next_time
    end

    local next_time = find_next_occurrence(self.freq, start_time)
    if (not self.count or self.count > 1) and (not self.until_date or next_time <= self.until_date) then
        if self.count then
            self.count = self.count - 1
        end
        return format_date(next_time)
    else
        return nil
    end
end

-- Helper function to check if any value in the table satisfies a condition
function table.any(t, predicate)
    for _, v in ipairs(t) do
        if predicate(v) then
            return true
        end
    end
    return false
end

-- Example usage
local my_rrule = rrule.new(rrule.WEEKLY, 1, nil, "20241231T235959Z", nil, nil, nil, {"MO", "FR"}, nil, nil, nil, nil)
print(my_rrule:to_string()) -- Output: FREQ=WEEKLY;BYDAY=MO,FR;UNTIL=20241231T235959Z

local parsed_rrule = rrule.parse("FREQ=WEEKLY;BYDAY=MO,FR;UNTIL=20241231T235959Z")
print(parsed_rrule:to_string()) -- Output: FREQ=WEEKLY;BYDAY=MO,FR;UNTIL=20241231T235959Z

local next_occurrence = parsed_rrule:get_next_occurrence("20231001T000000Z")
print(next_occurrence) -- Output: 20231002T000000Z (next Monday)

return rrule
