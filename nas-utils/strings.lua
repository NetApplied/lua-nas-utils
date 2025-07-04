-- nas-utils.strings.lua

local NASStrings      = {}

NASStrings._AUTHORS   = "liaozhaoyan, Michael Stephan"
NASStrings._VERSION   = "0.3.2-1"
NASStrings._LICENSE   = "MIT License"
NASStrings._COPYRIGHT = "Copyright (c) 2023 liaozhaoyan, (c) 2025 Net Applied Solutions"


local sub = string.sub
local gsub = string.gsub
local match = string.match
local lower = string.lower
local upper = string.upper
local format = string.format
local tostring = tostring
local error = error
local type = type
local ipairs = ipairs

-- If the string length is greater than that critical value,
-- The time cost of a string reversal operation will be very high
local criticalSizeofReverse = 4096

local function setupDelimiter(delimiter)
    if delimiter then
        return gsub(delimiter, "([%W])", "%%%1")
    else
        return "%s+"
    end
end

local function setupPatten(s)
    if s == nil then
        return "[%s\t\n]"
    else
        return setupDelimiter(s)
    end
end

local function setupRepl(repl)
    if type(repl) ~= "string" then
        error("repl must be a string.")
    else
        return gsub(repl, "([%W])", "%%%1") -- repl:gsub("([%W])", "%%%1")
    end
end

--- Rotates the characters of 's' 'n' positions circulary.
--- --
--- @param s string
--- @param n integer
--- @return string
function NASStrings.shift(s, n) -- positive for right, negative for left
    local len = #s
    if len == 0 then
        return s
    end
    n = n % len
    if n == 0 then
        return s
    elseif n > 0 then -- "abcd >> 1"
        local offset = len - n
        local s1 = sub(s, offset + 1)
        local s2 = sub(s, 1, offset)
        return format("%s%s", s1, s2)
    else -- "abcd << 1"
        local offset = len + n
        local s1 = sub(s, offset + 1)
        local s2 = sub(s, 1, offset)
        return format("%s%s", s1, s2)
    end
end

--- True if the string has only lowercase characters, false if not.
--- --
--- @param s string
--- @return boolean
function NASStrings.islower(s)
    local matched = match(s, "^[%l%s%p]+$")
    return matched and true or false
end

--- True if the string has only uppercase characters, false if not.
--- --
--- @param s string
--- @return boolean
function NASStrings.isupper(s)
    local matched = match(s, "^[%u%s%p]+$")
    return matched and true or false
end

--- If the string has only digits it returns true, otherwise it will be
--- false.
--- --
--- @param s string
--- @return boolean
function NASStrings.isdigit(s)
    local matched = match(s, "^%d+$")
    return matched and true or false
end

--- If the string is an integer expression it returns true, otherwise false.
--- --
--- @param s string
--- @return boolean
function NASStrings.isinteger(s)
    local matched = match(s, "^[%-%+]?%d+$")
    return matched and true or false
end

--- If the string is an hexadecimal expression, the function returns true,
--- otherwise it returns false.
--- --
--- @param s string
--- @return boolean
function NASStrings.ishex(s)
    local matched = match(s, "^%x+$")
    return matched and true or false
end

--- If the string is a combination of alphanumeric characters, the function
--- returns true, otherwise it returns false.
--- --
--- @param s string
--- @return boolean
function NASStrings.isalnum(s)
    local matched = match(s, "^%w+$")
    return matched and true or false
end

--- If the string is a title expression, the function  returns true, otherwise
--- it returns false.
--- --
--- @param s string
--- @return boolean
function NASStrings.istitle(s)
    local matched = match(s, "^%u%l*$")
    return matched and true or false
end

--- If the string has a float expression, the function will return true, in other
--- case it will be false.
--- --
--- @param s string
--- @return boolean
function NASStrings.isfloat(s)
    local re = "^[%-%+]?%d*%.%d+$"
    return match(s, re) ~= nil
end

--- Lua string.lower wrapper
--- --
--- @param s string
--- @return string
function NASStrings.lower(s)
    return lower(s)
end

--- Lua string.lower wrapper
--- --
--- @param s string
--- @return string
function NASStrings.casefold(s)
    return lower(s)
end

--- Lua string.upper wrapper
--- --
--- @param s string
--- @return string
function NASStrings.upper(s)
    return upper(s)
end

--- Set to upper case the lower case letters and vice versa.
--- --
--- @param s string
--- @return string
function NASStrings.swapcase(s)
    local function swapchar(c)
        local lc = lower(c)
        return (lc == c) and upper(c) or lc
    end

    local result = gsub(s, "%a", swapchar)
    return result
end

--- Capitalize `s` word.
--- --
--- @param s string
--- @return string
function NASStrings.capitalize(s)
    if #s < 1 then
        return s
    end
    local s1 = sub(s, 1, 1)
    local s2 = sub(s, 2)
    return format("%s%s", upper(s1), s2)
end

local string_find = string.find
local concat = table.concat
local floor = math.floor
local rep = string.rep
--- Convert the given `s` string in a table of substrings
--- delimited by `delimiter`. The maximum number of substrings is
--- defined by `n` which is MaxInteger by default.
--- --
--- @param s string
--- @param delimiter? string
--- @param n? integer # Default MaxInteger
function NASStrings.split(s, delimiter, n)
    local result = {}
    delimiter = setupDelimiter(delimiter)

    local nums = 0
    local beg = 1
    local c = 1

    if n then --n must be an integer greater than 0
        if type(n) ~= "number" or n <= 0 or n ~= floor(n) then
            error(format("bad input %s", tostring(n)))
        end
    end

    while (true) do
        local iBeg, iEnd = string_find(s, delimiter, beg)
        if (iBeg) then -- matched
            result[c] = sub(s, beg, iBeg - 1)
            c = c + 1
            beg = iEnd + 1
            nums = nums + 1
            if n and nums >= n then
                result[c] = sub(s, beg, #s)
                c = c + 1
                break
            end
        else
            result[c] = sub(s, beg, #s)
            c = c + 1
            break
        end
    end
    return result
end

local split = NASStrings.split

--- Divide s by `del` delimiter returning the left side,
--- the delimiter and the right side.
--- --
--- @param s string
--- @param del? string
--- @return table<string> | nil
function NASStrings.partition(s, del)
    local result = {}
    del = del or " "
    local delimiter = setupDelimiter(del)
    local iBeg, iEnd = string_find(s, delimiter)
    if iBeg then
        result[1] = sub(s, 1, iBeg - 1)
        result[2] = del
        result[3] = sub(s, iEnd + 1)
        return result
    else
        return nil
    end
end

local function reverseTable(t)
    local n = #t
    for i = 1, n / 2 do
        t[i], t[n + 1 - i] = t[n + 1 - i], t[i]
    end
end

local reverse = string.reverse
--- Convert the given `s` string in a table of substrings from right
--- --
--- @param s string
--- @param delimiter string?
--- @param n integer? # default is MaxInteger
--- @return table<string>
function NASStrings.rsplit(s, delimiter, n)
    if not n then -- if n is nil, Equivalent to split
        return split(s, delimiter)
    end

    if type(n) ~= "number" or n <= 0 or n ~= floor(n) then
        error(format("bad input %s", tostring(n)))
    end

    local result = {}
    local len = #s + 1
    if len >= criticalSizeofReverse then -- a big string? Reversing a string can be time-consuming
        local res = split(s, delimiter)
        local resLen = #res
        n = n + 1 -- The length of the returned array is equal to the number of splits plus one
        if resLen <= n then
            return res
        end

        if delimiter then   -- not blank?
            result[1] = concat(res, delimiter, 1, resLen - n + 1)
        else                -- blank,
            local cells = {}
            local pos = nil -- MJS 20250613 changed to satisfy LLS
            pos = 1
            local next
            local c = 1

            for i = 1, resLen - n + 1 do
                cells[c] = res[i]
                c = c + 1

                pos = pos + #res[i]
                next = string_find(s, "%S", pos)
                cells[c] = rep(" ", next - pos)
                c = c + 1
                pos = next
            end
            result[1] = concat(cells, "", 1, #cells - 1)
        end
        for i = 1, n do
            result[1 + i] = res[n + i]
        end
        return result
    end

    -- else reverse the string may be a better way
    local rs = reverse(s)
    local rDel = delimiter and reverse(delimiter) or nil
    rDel = setupDelimiter(rDel)
    local nums = 0
    local beg = 1
    local c = 1

    while (true) do
        local iBeg, iEnd = string_find(rs, rDel, beg)
        if (iBeg) then
            result[c] = sub(s, len - (iBeg - 1), len - beg)
            c = c + 1
            beg = iEnd + 1
            nums = nums + 1
            if nums >= n then
                result[c] = sub(s, 1, len - beg)
                break
            end
        else
            result[c] = sub(s, 1, len - beg)
            c = c + 1
            break
        end
    end

    reverseTable(result)
    return result
end

---
--- @param del? string
--- @return table<string> | nil
function NASStrings.rpartition(s, del)
    local result = {}
    del = del or " "
    local rs = reverse(s)
    local rDel = reverse(del)
    local delimiter = setupDelimiter(rDel)
    local len = #s

    local iBeg, iEnd = string_find(rs, delimiter)
    if iBeg then
        result[1] = sub(s, 1, len - iBeg + 1 - #del)
        result[2] = del
        result[3] = sub(s, len - iEnd + 1 + #del)
        return result
    else
        return nil
    end
end

local capitalize = NASStrings.capitalize
--- Capitalize all of words in `s`.
--- --
--- @param s string
--- @return string
function NASStrings.title(s)
    if #s < 1 then
        return s
    end

    local ss = split(s, " ")
    for i = 1, #ss do
        ss[i] = capitalize(ss[i])
    end
    return concat(ss, " ")
end

--- Capitalize line by line all the lines in `s`.
--- --
--- @param s string
--- @return string
function NASStrings.capwords(s)
    local lines = split(s, "\n")
    local rLines = {}
    for i, line in ipairs(lines) do
        local rWords = {}
        local words = split(line, " ")
        for j, word in ipairs(words) do
            rWords[j] = capitalize(word)
        end
        rLines[i] = concat(rWords, " ")
    end
    return concat(rLines, "\n")
end

--- Justify `s` by left with `len` copies of `ch`.
--- --
--- @param s string
--- @param len integer
--- @param ch? string # Default " "
--- @return string
function NASStrings.ljust(s, len, ch)
    ch = ch or " "
    if #ch ~= 1 then
        error(format("pad string master a single word, not %s", tostring(ch)))
    end
    local delta = len - #s
    if delta > 0 then
        local pad = rep(ch, delta)
        return format("%s%s", pad, s)
    else
        return s
    end
end

--- Justify `s` by right with `len` copies of `ch`.
--- --
--- @param s string
--- @param len integer
--- @param ch? string # Default " "
--- @return string
function NASStrings.rjust(s, len, ch)
    ch = ch or " "
    if #ch ~= 1 then
        error(format("pad string master a single word, not %s", tostring(ch)))
    end
    local delta = len - #s
    if delta > 0 then
        local pad = rep(ch, delta)
        return format("%s%s", s, pad)
    else
        return s
    end
end

--- Center `s` lines with `len` copies of `ch` in the longest line.
--- --
--- @param s string
--- @param len integer
--- @param ch? string # Default " "
--- @return string
function NASStrings.center(s, len, ch)
    ch = ch or " "
    if #ch ~= 1 then
        error(format("pad string master a single word, not %s", tostring(ch)))
    end
    local delta = len - #s
    if delta > 0 then
        local left = floor(delta / 2)
        local right = delta - left

        local res = { rep(ch, left), s, rep(ch, right) }
        return concat(res)
    else
        return s
    end
end

local ljust = NASStrings.ljust
--- Justify by left with zeros.
--- --
--- @param s string
--- @param len integer
--- @return string
function NASStrings.zfill(s, len)
    return ljust(s, len, "0")
end

--- Split string line by line
--- --
--- @param s string
--- @return table<string>
function NASStrings.splitlines(s)
    return split(s, '\n')
end

--- Remove first `chars` string of `s`.
--- --
--- @param s string
--- @param chars string?
--- @return string
function NASStrings.lstrip(s, chars)
    local patten = concat({ "^", setupPatten(chars), "+" })
    local _, ends = string_find(s, patten)
    if ends then
        return sub(s, ends + 1, -1)
    else
        return s
    end
end

--- Remove last `chars` string of `s`.
--- --
--- @param s string
--- @param chars string?
--- @return string
function NASStrings.rstrip(s, chars)
    local patten = format("%s%s", setupPatten(chars), "+$")
    local last = string_find(s, patten)
    if last then
        return sub(s, 1, last - 1)
    else
        return s
    end
end

local lstrip = NASStrings.lstrip
local rstrip = NASStrings.rstrip
--- Remove last and first `chars` string of `s`, it's a consecutive
--- `lstrip` and `rstrip`.
--- --
--- @param s string
--- @param chars string?
--- @return string
function NASStrings.strip(s, chars)
    local res = lstrip(s, chars)
    return rstrip(res, chars)
end

--- Joins an array of *string* `strings` with `delim` between.
--- --
--- @param delim string
--- @param strings table<string>
--- @return string
function NASStrings.join(delim, strings)
    return concat(strings, delim)
end

--- Check if `s1` begin with `s2`.
--- --
--- @param s1 string
--- @param s2 string
--- @return string | boolean
function NASStrings.startswith(s1, s2)
    return sub(s1, 1, #s2) == s2
end

--- Check if `s1` ends with `s2`.
--- --
--- @param s1 string
--- @param s2 string
--- @return string | boolean
function NASStrings.endswith(s1, s2)
    return s2 == '' or sub(s1, - #s2) == s2
end

--- Get the first ocurrence of `s2` in `s1` beginning from `start`
--- and finishing at `stop`.
--- --
--- @param s1 string
--- @param s2 string
--- @param start? integer # Default 1
--- @param stop? integer # Default -1 --> end
--- @return integer
function NASStrings.find(s1, s2, start, stop)
    start = start or 1
    stop = stop or -1
    s1 = sub(s1, start, stop)
    local res = string_find(s1, s2, 1, false)
    return res or -1
end

local pystring_find = NASStrings.find
--- Get the first ocurrence of `s2` in `s1` beginning from `start`
--- and finishing at `stop` but working with the reversed version of
--- `s1`.
--- --
--- @param s1 string
--- @param s2 string
--- @param start? integer # Default 1
--- @param stop? integer # Default -1 --> end
--- @return integer
function NASStrings.rfind(s1, s2, start, stop)
    start = start or 1
    stop = stop or -1
    s1 = sub(s1, start, stop)

    local len = #s1

    if len >= criticalSizeofReverse then --  a big string?
        local res = -1
        local current_pos = nil          -- MJS 20250613 changed to satisfy LLS
        current_pos = 0

        while true do
            local start_pos, end_pos = string_find(s1, s2, current_pos + 1, false)
            if not start_pos then
                break
            end
            res = start_pos
            current_pos = end_pos
        end
        return res
    end

    local lFind = #s2
    local rs1, rs2 = reverse(s1), reverse(s2)
    local i = string_find(rs1, rs2, 1, false)
    if i then
        return len - i - lFind + 1
    else
        return -1
    end
end

--- Get the first ocurrence of `s2` in `s1` starting at `start`
--- and finishing at `stop`.
--- --
--- @param s1 string
--- @param s2 string
--- @param start integer
--- @param stop integer
--- @return integer
function NASStrings.index(s1, s2, start, stop)
    local res = pystring_find(s1, s2, start, stop)
    if res < 0 then
        error(format("%s is  not in %s", tostring(s2), tostring(s1)))
    end
    return res
end

local pystring_rfind = NASStrings.rfind
--- Get the index of first `s2` ocurrence in `s1` beginning from `start`
--- and ending at `stop`
--- --
--- @param s1 string
--- @param s2 string
--- @param start integer
--- @param stop integer
--- @return integer
function NASStrings.rindex(s1, s2, start, stop)
    local res = pystring_rfind(s1, s2, start, stop)
    if res < 0 then
        error(format("%s is  not in %s", tostring(s2), tostring(s1)))
    end
    return res
end

local gmatch = string.gmatch
--- Count how many times the pattern appears in the target
--- string.
--- --
--- @param s string
--- @param find string
--- @return integer
function NASStrings.count(s, find)
    local i = 0
    local patten = setupPatten(find)
    for _ in gmatch(s, patten) do
        i = i + 1
    end
    return i
end

local gsub = string.gsub
--- Replaces the first n occurrences which matches with 'find' pattern
--- and substitutes them by repl.
--- --
--- @param s string
--- @param find string # Regular expression
--- @param repl string # Replacement
--- @param n integer? # Number of occurrences until stop counting.
--- @return string, integer
function NASStrings.replace(s, find, repl, n)
    local patten = setupPatten(find)
    repl = setupRepl(repl)

    return gsub(s, patten, repl, n)
end

--- Expand blank spaces in the string by 'tabs' times.
--- --
--- @param s string
--- @param tabs? integer # Default is 4
--- @return string, integer
function NASStrings.expandtabs(s, tabs)
    tabs = tabs or 4
    local repl = rep(" ", tabs)
    return gsub(s, "\t", repl)
end

--- default callback function for pystring.with, mode lines
--- --
--- @param line string
--- @return string or nil, nil will break lines loop
local function withLines(line)
    return line
end

--- default callback function for pystring.with, mode raw
--- --
--- @param content string
--- @return string
local function withRaw(content)
    return content
end

local io_open = io.open
-- Focus on the file content without worrying about the file descriptor.
-- `executor` function evals every line if `mode` is set to "line" or the full
-- file content if it is set to "raw" or `nil`.
--- @param file_name string # Name of the file
--- @param mode string? # {"lines", "raw" | nil} How the file will be processed, default raw.
--- @param executor function? # Function that works with the file descriptor,
--- @param file_opt string? # File options. See `io.open`, default `r`
--- @return any
function NASStrings.with(file_name, mode, executor, file_opt)
    mode = mode or "raw"
    file_opt = file_opt or "r"

    if not executor then
        if mode == "raw" then
            executor = withRaw
        elseif mode == "lines" then
            executor = withLines
        else
            error(format("bad mode %s for pystring.with", mode))
        end
    end

    if match(file_opt, 'w') or match(file_opt, 'a') then
        error("pystring.with doesn't work with writing mode files")
    end

    local f = io_open(file_name, file_opt)
    local r

    if f then
        if mode == 'lines' then
            r = {}
            local c = 1
            for l in f:lines() do
                local res = executor(l) -- note that r can be skipped on executor implementation
                if res then
                    r[c] = res
                    c = c + 1
                else
                    break
                end
            end
        elseif (not mode or mode == 'raw') then
            local _raw_file, err = f:read("*a")
            if not _raw_file then
                f:close()
                error(format("Problems reading %s, report: %s", file_name, tostring(err)))
            end
            r = executor(_raw_file)
        else
            f:close()
            error(format('Invalid mode = %s option', mode))
        end
    else
        error(format("Problems opening %s", tostring(file_name)))
    end
    f:close()
    return r
end

return NASStrings
