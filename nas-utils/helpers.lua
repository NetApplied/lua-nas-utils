-- nas-utils.helpers.lua

local NASHelpers      = {}

NASHelpers._AUTHORS   = "Michael Stephan"
NASHelpers._VERSION   = "0.3.2-1"
NASHelpers._LICENSE   = "MIT License"
NASHelpers._COPYRIGHT = "Copyright (c) 2025 Net Applied Solutions, LLC"

local socket          = require("socket") -- luasocket
local rand            = require("openssl.rand") -- luaossl


--[[
********************
*** STRING UTILS ***
********************
]]


---Escape Lua special pattern characters in 'input_str'
---@param input_str string
---@return string
NASHelpers.escape_lua_pattern = function(input_str)
  -- Escape special pattern characters in 'input_str'

  -- Define a set of Lua pattern characters that need to be escaped.
  local special_chars = { "%", "+", "-", "?", "(", ")", "[", "]", "^", "$", "."
  , "{", "}" }

  -- Build a pattern dynamically from the special_chars table.
  local pattern = ""
  for _, char in ipairs(special_chars) do
    pattern = pattern .. "%" .. char
  end

  -- Replace each special character with its escaped version.
  return (input_str:gsub("([" .. pattern .. "])", "%%%1"))
end -- NASHelpers.escape_lua_pattern


---Replace search_str with replacement_str in input_str
---@param input_str string
---@param search_str string
---@param replacement_str string
---@return unknown
NASHelpers.replace = function(input_str, search_str, replacement_str)
  -- Escape Lua pattern characters in the search string.
  local escaped_search = NASHelpers.escape_lua_pattern(search_str)
  -- Use gsub with the escaped search pattern
  local result = input_str:gsub(escaped_search, replacement_str)
  return result
end -- NASHelpers.replace


--Trim any matching trim_chars from input_str from beginning and ending of input_str
---@param input_str string
---@param trim_chars string?
---@return string
NASHelpers.trim = function(input_str, trim_chars)
  if not input_str then return "" end

  -- chars = chars or "%s"  -- default to whitespace
  -- Default to whitespace if no characters are specified
  trim_chars = trim_chars or " \t\n\r"

  -- Escape special pattern characters in 'trim_chars'
  --trim_chars = string.gsub(trim_chars, "([%+%-%*%?%[%]%.%$])", "%%%1")
  local escaped_trim_chars = NASHelpers.escape_lua_pattern(trim_chars)

  return input_str:match(
    "^[" .. escaped_trim_chars .. "]*(.-)[" .. escaped_trim_chars .. "]*$"
  )
end


--Trim any matching trim_chars from input_str from beginning of input_str
---@param input_str string
---@param trim_chars string?
---@return string
NASHelpers.ltrim = function(input_str, trim_chars)
  if not input_str then return "" end

  trim_chars = trim_chars or " \t\n\r"

  -- Escape special pattern characters in 'trim_chars'
  --trim_chars = string.gsub(trim_chars, "([%+%-%*%?%[%]%.%$])", "%%%1")
  local escaped_trim_chars = NASHelpers.escape_lua_pattern(trim_chars)

  return input_str:match("[" .. escaped_trim_chars .. "]*(.*)")
end -- NASHelpers.ltrim


--Trim any matching trim_chars from input_str from ending of input_str
---@param input_str string
---@param trim_chars string?
---@return string
NASHelpers.rtrim = function(input_str, trim_chars)
  if not input_str then return "" end

  trim_chars = trim_chars or " \t\n\r"

  -- Escape special pattern characters in 'trim_chars'
  -- trim_chars = string.gsub(trim_chars, "([%+%-%*%?%[%]%.%$])", "%%%1")
  local escaped_trim_chars = NASHelpers.escape_lua_pattern(trim_chars)

  return input_str:match("(.-)[" .. escaped_trim_chars .. "]*$")
end -- NASHelpers.rtrim


--[[
Description - split_string:
  - Will split a string by a delimiter.

Parameters:
  - input_str: string - the string to split.
  - delimiter: string - the delimiter to use for splitting.

  Returns:
  - result: table of strings - the split string.

Throws:
  - If the input string is empty or not a string, it will throw an error.
]]
---comment
---@param input_str string
---@param delimiter string
---@return table
function NASHelpers.split_string(input_str, delimiter)
  if input_str == nil or type(input_str) ~= "string" then
    error("input_str must not be empty and must be a string")
  end -- if

  -- if delimiter is null, set it as space
  if delimiter == nil then
    delimiter = '%s'
  end

  -- define an array
  local t = {}

  -- split string based on delimiter
  for str in string.gmatch(input_str, '([^' .. delimiter .. ']+)') do
    -- insert the substring in table
    table.insert(t, str)
  end

  -- return the array
  return t
end

--[[
************************
*** END STRING UTILS ***
************************
]]



--[[
*******************
*** TABLE UTILS ***
*******************
]]

---Description: Returns the size of a dictionary table
---@param dict table Dictionary to get the size of
---@param break_if_not_zero boolean? Defaults to false. Only check if not zero
---@return number
NASHelpers.dict_size = function(dict, break_if_not_zero)
  if dict == nil or type(dict) ~= "table" then return 0 end

  local size = 0
  for _ in pairs(dict) do
    size = size + 1
    if break_if_not_zero then return size end
  end
  return size
end


---Returns true if dictionary table is empty or nil <br><br>
---Throws: error if dict is not a table
---@param dict table
---@return boolean
NASHelpers.dict_is_empty = function(dict)
  if type(dict) ~= "table" then error("dict is not a table") end
  if dict == nil then return true end

  return NASHelpers.dict_size(dict, true) == 0
end


---Sort a dictionary by keys or values.
---Can also be reverse sorted.
---Comparisons are case-sensitive by default.<br>
---Throws: error if dict is not a dictionary.
---@param dict table Must be a dictionary
---@param sort_by_value boolean? Optional, defaults to false
---@param reverse_sort boolean? Optional, defaults to false
---@param case_sensitive boolean? Optional, defaults to true
---@return table
NASHelpers.dict_sort = function(dict, sort_by_value, reverse_sort, case_sensitive)
  if type(dict) ~= "table" then error("dict is not a table") end
  if #dict > 0 then error("dict is not a dictionary") end
  if NASHelpers.dict_is_empty(dict) then return {} end

  if case_sensitive == nil then case_sensitive = true end

  local sort_index = 1                     -- sort by key
  if sort_by_value then sort_index = 2 end -- sort by value

  local sorted_table = {}

  -- Create a list of table indices and corresponding values
  for key, value in pairs(dict) do
    sorted_table[#sorted_table + 1] = { key, value }
  end

  -- Sort the list based on values
  table.sort(sorted_table,
    function(a, b)
      a = a[sort_index]
      b = b[sort_index]

      -- if a or b are not comparable, convert all to strings for comparison
      if not ((type(a) == "number" and type(b) == "number") or
            (type(a) == "string" and type(b) == "string")) then
        a = tostring(a)
        b = tostring(b)
      end


      if case_sensitive == false and type(a) == "string" and type(b) == "string" then
        a = string.upper(a)
        b = string.upper(b)
      end

      if reverse_sort then
        return b < a
      else
        return a < b
      end
    end
  )

  -- Dictionaries cannot retain order, need to return as a list instead
  -- local sorted_dict = {}
  -- for _, d in ipairs(sorted_table) do
  --   sorted_dict[d[1]] = d[2]
  -- end

  return sorted_table
end


---Description: Returns true if table is a non-empty list
---@param table table
---@return boolean
NASHelpers.table_is_list = function(table)
  return table and type(table) == "table" and #table > 0
end


---Description: Returns true if table is a dictionary or is an empty table
---@param table table
---@return boolean
NASHelpers.table_is_dict = function(table)
  return table and type(table) == "table" and #table == 0
end

--[[
***********************
*** END TABLE UTILS ***
***********************
]]



--[[
**********************
*** DATETIME UTILS ***
**********************
]]

--[[
Description - unixtime_milliseconds:
  - Returns the current unix time in milliseconds.

]]
---@return integer
function NASHelpers.unixtime_milliseconds()
  --[[
    -- INTERNAL implementation.
    -- os.clock() does not have good accuracy
    local _, milliseconds = math.modf(os.clock() * 1000)
    return math.floor((milliseconds + os.time()) * 1000)
  ]]

  return math.floor(socket.gettime() * 1000)
end

-- Gets UTC offset for local system timezone
---@param datetime_table table? datetime table to determine dst value for specified date
---@return nil
function NASHelpers.utc_offset(datetime_table)
  if datetime_table and type(datetime_table) ~= 'table' then return nil end
  local offset = nil
  local lt = nil

  -- If datetime_table is provided, use it to determine dst value for date
  if datetime_table then
    datetime_table.year = datetime_table.year or 0
    datetime_table.month = datetime_table.month or 0
    datetime_table.day = datetime_table.day or 0

    -- get datetime table for date, to get isdst value
    lt = os.date("*t", os.time({
      year = datetime_table.year,
      month = datetime_table.month,
      day = datetime_table.day
    }))
  else
    -- use current system time isdst value
    lt = os.date("*t") -- get current system time table
  end

  offset = os.time({
    year = 1970,
    month = 1,
    day = 1,
    hour = 0,
    min = 0,
    sec = 0,
    isdst = lt.isdst
  })

  return offset
end

-- Returns ISO 8601 (RFC 3339) date string (YYYY-MM-DD HH:MM:SS) from unix timestamp
---@param unix_timestamp number? Unix timestamp to convert. If nil, returns current time.
---@param local_time boolean? If true, return local time. Default is false (UTC).
---@return string? date_str ISO 8601 date string (YYYY-MM-DD HH:MM:SS), or nil if no timestamp
function NASHelpers.unixtime_to_sql8601(unix_timestamp, local_time)
  local local_string = local_time and "" or "!"
  unix_timestamp = unix_timestamp or os.time()

  local datetime_format = local_string .. "%Y-%m-%d %H:%M:%S"

  return tostring(os.date(datetime_format, unix_timestamp))
end

-- Parse ISO 8601 (RFC 3339) date string (YYYY-MM-DD HH:MM:SS) to unix timestamp.
-- Assumes system time is UTC
---@param date_str string ISO 8601 date string (YYYY-MM-DD HH:MM:SS) in UTC
---@return number? unix_timestamp timestamp in seconds if valid date_str, otherwise nil.
function NASHelpers.unixtime_from_sql8601(date_str)
  local year = tonumber(date_str:sub(1, 4)) or 0
  local month = tonumber(date_str:sub(6, 7)) or 0
  local day = tonumber(date_str:sub(9, 10)) or 0
  local hour = tonumber(date_str:sub(12, 13)) or 0
  local minute = tonumber(date_str:sub(15, 16)) or 0
  local second = tonumber(date_str:sub(18, 19)) or 0

  -- year, month, day are required for os.time() function
  if year == 0 or month == 0 or day == 0 then return nil end

  local offset = NASHelpers.utc_offset({ year = year, month = month, day = day })

  local date_utc_ts = os.time({
    year = year,
    month = month,
    day = day,
    hour = hour,
    min = minute,
    sec = second
  })

  date_utc_ts = date_utc_ts - offset

  return date_utc_ts
end

--[[
**************************
*** END DATETIME UTILS ***
**************************
]]



--[[
********************
*** NUMBER UTILS ***
********************
]]

--[[
Description - roundFP:
  - Will round a number to the specified precision.

Parameters:
  - value: number - the value to round.
  - precision: number? - the precision to round to. Default is 1.
  - round_up: boolean? - whether to round up or not. Default is true.

  Returns:
  - result: number - the rounded number.

Throws:
  - If the value is empty or not a number, it will throw an error.
  - If the precision is not empty and not a number, it will throw an error.

]]
---@param value number
---@param precision number?
---@param round_up boolean?
---@return number
function NASHelpers.roundFP(value, precision, round_up)
  if value == nil or type(value) ~= "number" then
    error("value must not be empty and must be a number")
  end -- if

  if precision ~= nil and type(precision) ~= "number" then
    error("precision must be empty or must be a number")
  end -- if

  local round_value = 0.501
  precision = precision or 1

  if round_up == false then
    round_value = 0.0
  end

  if precision == 0 then
    return math.floor(value + round_value)
  end -- if

  return math.floor((value * (10 ^ precision)) + round_value) / (10 ^ precision)
end

--[[
************************
*** END NUMBER UTILS ***
************************
]]


--[[
********************
*** SYSTEM UTILS ***
********************
]]

--[[
Description - wait:
  - Waits for a specified amount of milliseconds. 1000 milliseconds = 1 second.

Parameters:
  - milliseconds: number - time to wait in milliseconds

Returns:
  - None
]]
---@param milliseconds number
function NASHelpers.wait(milliseconds)
  local ms = NASHelpers.roundFP((milliseconds / 1000), 3)
  socket.sleep(ms)
end

--[[
Description - clone_function:
  - Clones a function. Upvalues will be retained as well.

Parameters:
  - func: function - function to be cloned

  Returns:
  - function - a clone of the function

  Throws:
  - error: string - If func is not a function, or if function cannot be cloned
]]
---@param func function
---@return function
function NASHelpers.clone_function(func)
  if type(func) ~= "function" then
    error("func must be a function")
  end

  local cloned_function = loadstring(string.dump(func))
  if not cloned_function then
    error("unable to clone function")
  end

  -- check if there are any function upvalues that need to be cloned
  local i = 1
  while true do
    -- see if i is a valid upvalue index
    local uvi = debug.getupvalue(func, i)
    if not uvi then
      break
    end
    -- join the clone and the original
    debug.upvaluejoin(cloned_function, i, func, i)
    i = i + 1
  end

  return cloned_function
end

-- INTERNAL FUNCTIONS --

--[[
Description - _exec_popen:
  - Internal function will return the result of a command that is passed to it.

Parameters:
  - command: string - the command to execute.
  - multi_line: boolean - Keep newline for multi-line output. Default is false.

Returns:
  - result: string - the result of the command.

Throws:
  - If the command is empty or not a string, it will throw an error.
]]
---@param command string
---@param multi_line boolean?
---@return string
function NASHelpers._exec_popen(command, multi_line)
  if command == nil or type(command) ~= "string" then
    error("command must not be empty and must be a string")
  end -- if

  -- don't keep newline character to separate multi-line output by default
  if multi_line == nil then multi_line = false end

  local result = ""
  local f = io.popen(command)
  if not f then
    error("Could not open file")
  end -- if

  -- Does not work in 5.1 - only line is returned not next_line, like other lua versions
  -- for line, next_line in f:lines() do
  --   result = result .. line

  --   if next_line and multi_line then
  --     result = result .. "\n"
  --   end
  -- end -- for loop

  local line = f:read("*line")

  while line do
    result = result .. line

    line = f:read("*line")
    if line and multi_line then
      result = result .. "\n"
    end
  end

  f:close()

  return result
end

--[[
************************
*** END SYSTEM UTILS ***
************************
]]


return NASHelpers


--[[
***************************
*** Example _exec_popen ***
***************************


local function hash_password_cmd(password, salt)
  -- Switch to ARGON2I
  -- https://asecuritysite.com/openssl/argon
  -- openssl kdf -keylen 24 -kdfopt pass:Hello -kdfopt salt:NaCl1234
  --    -kdfopt iter:1 -kdfopt memcost:8192 ARGON2I
  if password == nil or type(password) ~= "string" or #password < 8 then
    error("password must not be empty and must be 8 or more characters")
  end

  if salt == nil or type(salt) ~= "string" then
    error("salt must not be empty and must be a string")
  end

  local hash
  local replace = require("nas-utils.strings").replace
  local escaped_password = replace(password, '"', '\\"')
  local escaped_salt = replace(salt, '"', '\\"')
  local cmd = 'openssl passwd -6 -salt "'
      .. escaped_salt .. '" "'
      .. escaped_password .. '"'

  -- print("cmd", cmd)
  hash = NASHelpers._exec_popen(cmd)

  return hash
end
]]