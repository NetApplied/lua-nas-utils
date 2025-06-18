# nas-utils.helpers

A Lua module providing helper utilities for strings, tables, datetime, numbers, and system operations.

## Table of Contents

- [escape_lua_pattern](#escape_lua_pattern)
- [replace](#replace)
- [trim](#trim)
- [ltrim](#ltrim)
- [rtrim](#rtrim)
- [split_string](#split_string)
- [dict_size](#dict_size)
- [dict_is_empty](#dict_is_empty)
- [dict_sort](#dict_sort)
- [table_is_list](#table_is_list)
- [table_is_dict](#table_is_dict)
- [unixtime_milliseconds](#unixtime_milliseconds)
- [utc_offset](#utc_offset)
- [unixtime_to_sql8601](#unixtime_to_sql8601)
- [unixtime_from_sql8601](#unixtime_from_sql8601)
- [roundFP](#roundfp)
- [wait](#wait)
- [clone_function](#clone_function)
- [_exec_popen](#_exec_popen)
- [Usage Example](#usage-example)

---

## escape_lua_pattern

**Escape Lua special pattern characters in a string.**

```lua
NASHelpers.escape_lua_pattern(input_str)
```

- `input_str` (`string`): String to escape.
- **Returns:** `string` Escaped string.

---

## replace

**Replace all occurrences of a substring with another string.**

```lua
NASHelpers.replace(input_str, search_str, replacement_str)
```

- `input_str` (`string`): Source string.
- `search_str` (`string`): Substring to search for.
- `replacement_str` (`string`): Replacement string.
- **Returns:** `string` Resulting string.

---

## trim

**Trim characters from both ends of a string.**

```lua
NASHelpers.trim(input_str, trim_chars)
```

- `input_str` (`string`): String to trim.
- `trim_chars` (`string?`): Characters to trim (default: whitespace).
- **Returns:** `string` Trimmed string.

---

## ltrim

**Trim characters from the start of a string.**

```lua
NASHelpers.ltrim(input_str, trim_chars)
```

- `input_str` (`string`): String to trim.
- `trim_chars` (`string?`): Characters to trim (default: whitespace).
- **Returns:** `string` Trimmed string.

---

## rtrim

**Trim characters from the end of a string.**

```lua
NASHelpers.rtrim(input_str, trim_chars)
```

- `input_str` (`string`): String to trim.
- `trim_chars` (`string?`): Characters to trim (default: whitespace).
- **Returns:** `string` Trimmed string.

---

## split_string

**Split a string by a delimiter.**

```lua
NASHelpers.split_string(input_str, delimiter)
```

- `input_str` (`string`): String to split.
- `delimiter` (`string`): Delimiter to split by.
- **Returns:** `table` Array of substrings.

---

## dict_size

**Get the number of keys in a dictionary.**

```lua
NASHelpers.dict_size(dict, break_if_not_zero)
```

- `dict` (`table`): Dictionary table.
- `break_if_not_zero` (`boolean?`): If true, returns as soon as a key is found.
- **Returns:** `number` Number of keys.

---

## dict_is_empty

**Check if a dictionary is empty.**

```lua
NASHelpers.dict_is_empty(dict)
```

- `dict` (`table`): Dictionary table.
- **Returns:** `boolean` True if empty.

---

## dict_sort

**Sort a dictionary by keys or values.**

```lua
NASHelpers.dict_sort(dict, sort_by_value, reverse_sort, case_sensitive)
```

- `dict` (`table`): Dictionary table.
- `sort_by_value` (`boolean?`): Sort by value (default: false).
- `reverse_sort` (`boolean?`): Reverse sort (default: false).
- `case_sensitive` (`boolean?`): Case sensitive (default: true).
- **Returns:** `table` Sorted array of `{key, value}` pairs.

---

## table_is_list

**Check if a table is a non-empty list.**

```lua
NASHelpers.table_is_list(table)
```

- `table` (`table`): Table to check.
- **Returns:** `boolean` True if list.

---

## table_is_dict

**Check if a table is a dictionary or empty.**

```lua
NASHelpers.table_is_dict(table)
```

- `table` (`table`): Table to check.
- **Returns:** `boolean` True if dictionary or empty.

---

## unixtime_milliseconds

**Get the current Unix time in milliseconds.**

```lua
NASHelpers.unixtime_milliseconds()
```

- **Returns:** `integer` Unix time in milliseconds.

---

## utc_offset

**Get UTC offset for the local system timezone.**

```lua
NASHelpers.utc_offset(datetime_table)
```

- `datetime_table` (`table?`): Date table (optional).
- **Returns:** `number?` UTC offset in seconds.

---

## unixtime_to_sql8601

**Convert Unix timestamp to ISO 8601 date string.**

```lua
NASHelpers.unixtime_to_sql8601(unix_timestamp, local_time)
```

- `unix_timestamp` (`number?`): Unix timestamp (default: now).
- `local_time` (`boolean?`): True for local time, false for UTC (default: false).
- **Returns:** `string?` ISO 8601 date string.

---

## unixtime_from_sql8601

**Parse ISO 8601 date string to Unix timestamp.**

```lua
NASHelpers.unixtime_from_sql8601(date_str)
```

- `date_str` (`string`): ISO 8601 date string.
- **Returns:** `number?` Unix timestamp.

---

## roundFP

**Round a number to the specified precision.**

```lua
NASHelpers.roundFP(value, precision, round_up)
```

- `value` (`number`): Value to round.
- `precision` (`number?`): Precision (default: 1).
- `round_up` (`boolean?`): Round up (default: true).
- **Returns:** `number` Rounded value.

---

## wait

**Wait for a specified number of milliseconds.**

```lua
NASHelpers.wait(milliseconds)
```

- `milliseconds` (`number`): Time to wait.
- **Returns:** `nil`

---

## clone_function

**Clone a function, retaining upvalues.**

```lua
NASHelpers.clone_function(func)
```

- `func` (`function`): Function to clone.
- **Returns:** `function` Cloned function.

---

## _exec_popen

**Execute a shell command and return its output.**

```lua
NASHelpers._exec_popen(command, multi_line)
```

- `command` (`string`): Command to execute.
- `multi_line` (`boolean?`): Keep newlines (default: false).
- **Returns:** `string` Command output.

---

## Usage Example

```lua
local helpers = require("nas-utils.helpers")

print(helpers.trim("  hello  ")) -- "hello"
print(helpers.dict_size({a=1, b=2})) -- 2
print(helpers.roundFP(3.14159, 2)) -- 3.14
helpers.wait(1000) -- waits 1 second
```

---

## License

MIT License

---

## Author

Michael Stephan, NetApplied Solutions
