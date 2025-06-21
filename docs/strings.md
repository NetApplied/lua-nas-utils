# nas-utils.strings

A Lua module providing a wide range of string manipulation utilities, similar to Python's string methods.

## Table of Contents

- [shift](#shift)
- [islower](#islower)
- [isupper](#isupper)
- [isdigit](#isdigit)
- [isinteger](#isinteger)
- [ishex](#ishex)
- [isalnum](#isalnum)
- [istitle](#istitle)
- [isfloat](#isfloat)
- [lower](#lower)
- [casefold](#casefold)
- [upper](#upper)
- [swapcase](#swapcase)
- [capitalize](#capitalize)
- [title](#title)
- [capwords](#capwords)
- [split](#split)
- [rsplit](#rsplit)
- [partition](#partition)
- [rpartition](#rpartition)
- [splitlines](#splitlines)
- [ljust](#ljust)
- [rjust](#rjust)
- [center](#center)
- [zfill](#zfill)
- [lstrip](#lstrip)
- [rstrip](#rstrip)
- [strip](#strip)
- [join](#join)
- [startswith](#startswith)
- [endswith](#endswith)
- [find](#find)
- [rfind](#rfind)
- [index](#index)
- [rindex](#rindex)
- [count](#count)
- [replace](#replace)
- [expandtabs](#expandtabs)
- [with](#with)
- [Usage Example](#usage-example)

---

## shift

**Circularly rotate a string by n positions.**

```lua
NASStrings.shift(s, n)
```

- `s` (`string`): String to rotate.
- `n` (`integer`): Number of positions (positive: right, negative: left).
- **Returns:** `string` Rotated string.

---

## islower

**Check if all characters are lowercase.**

```lua
NASStrings.islower(s)
```

- `s` (`string`): String to check.
- **Returns:** `boolean`

---

## isupper

**Check if all characters are uppercase.**

```lua
NASStrings.isupper(s)
```

- `s` (`string`): String to check.
- **Returns:** `boolean`

---

## isdigit

**Check if string contains only digits.**

```lua
NASStrings.isdigit(s)
```

- `s` (`string`): String to check.
- **Returns:** `boolean`

---

## isinteger

**Check if string is an integer expression.**

```lua
NASStrings.isinteger(s)
```

- `s` (`string`): String to check.
- **Returns:** `boolean`

---

## ishex

**Check if string is a hexadecimal expression.**

```lua
NASStrings.ishex(s)
```

- `s` (`string`): String to check.
- **Returns:** `boolean`

---

## isalnum

**Check if string is alphanumeric.**

```lua
NASStrings.isalnum(s)
```

- `s` (`string`): String to check.
- **Returns:** `boolean`

---

## istitle

**Check if string is title-cased.**

```lua
NASStrings.istitle(s)
```

- `s` (`string`): String to check.
- **Returns:** `boolean`

---

## isfloat

**Check if string is a float expression.**

```lua
NASStrings.isfloat(s)
```

- `s` (`string`): String to check.
- **Returns:** `boolean`

---

## lower

**Convert string to lowercase.**

```lua
NASStrings.lower(s)
```

- `s` (`string`): String to convert.
- **Returns:** `string`

---

## casefold

**Convert string to lowercase (alias for lower).**

```lua
NASStrings.casefold(s)
```

- `s` (`string`): String to convert.
- **Returns:** `string`

---

## upper

**Convert string to uppercase.**

```lua
NASStrings.upper(s)
```

- `s` (`string`): String to convert.
- **Returns:** `string`

---

## swapcase

**Swap case of all characters.**

```lua
NASStrings.swapcase(s)
```

- `s` (`string`): String to swap case.
- **Returns:** `string`

---

## capitalize

**Capitalize the first character.**

```lua
NASStrings.capitalize(s)
```

- `s` (`string`): String to capitalize.
- **Returns:** `string`

---

## title

**Capitalize the first character of each word.**

```lua
NASStrings.title(s)
```

- `s` (`string`): String to title-case.
- **Returns:** `string`

---

## capwords

**Capitalize the first character of each word in each line.**

```lua
NASStrings.capwords(s)
```

- `s` (`string`): String to process.
- **Returns:** `string`

---

## split

**Split string by delimiter, up to n times.**

```lua
NASStrings.split(s, delimiter?, n?)
```

- `s` (`string`): String to split.
- `delimiter` (`string?`): Delimiter (default: whitespace).
- `n` (`integer?`): Max splits.
- **Returns:** `table<string>`

---

## rsplit

**Split string from the right.**

```lua
NASStrings.rsplit(s, delimiter?, n?)
```

- `s` (`string`): String to split.
- `delimiter` (`string?`): Delimiter (default: whitespace).
- `n` (`integer?`): Max splits.
- **Returns:** `table<string>`

---

## partition

**Split string into three parts at first occurrence of delimiter.**

```lua
NASStrings.partition(s, del?)
```

- `s` (`string`): String to partition.
- `del` (`string?`): Delimiter (default: space).
- **Returns:** `table<string> | nil`

---

## rpartition

**Split string into three parts at last occurrence of delimiter.**

```lua
NASStrings.rpartition(s, del?)
```

- `s` (`string`): String to partition.
- `del` (`string?`): Delimiter (default: space).
- **Returns:** `table<string> | nil`

---

## splitlines

**Split string into lines.**

```lua
NASStrings.splitlines(s)
```

- `s` (`string`): String to split.
- **Returns:** `table<string>`

---

## ljust

**Left-justify string, padding with character.**

```lua
NASStrings.ljust(s, len, ch?)
```

- `s` (`string`): String to justify.
- `len` (`integer`): Total length.
- `ch` (`string?`): Padding character (default: space).
- **Returns:** `string`

---

## rjust

**Right-justify string, padding with character.**

```lua
NASStrings.rjust(s, len, ch?)
```

- `s` (`string`): String to justify.
- `len` (`integer`): Total length.
- `ch` (`string?`): Padding character (default: space).
- **Returns:** `string`

---

## center

**Center string, padding with character.**

```lua
NASStrings.center(s, len, ch?)
```

- `s` (`string`): String to center.
- `len` (`integer`): Total length.
- `ch` (`string?`): Padding character (default: space).
- **Returns:** `string`

---

## zfill

**Left-justify string with zeros.**

```lua
NASStrings.zfill(s, len)
```

- `s` (`string`): String to pad.
- `len` (`integer`): Total length.
- **Returns:** `string`

---

## lstrip

**Strip characters from the start.**

```lua
NASStrings.lstrip(s, chars?)
```

- `s` (`string`): String to strip.
- `chars` (`string?`): Characters to strip (default: whitespace).
- **Returns:** `string`

---

## rstrip

**Strip characters from the end.**

```lua
NASStrings.rstrip(s, chars?)
```

- `s` (`string`): String to strip.
- `chars` (`string?`): Characters to strip (default: whitespace).
- **Returns:** `string`

---

## strip

**Strip characters from both ends.**

```lua
NASStrings.strip(s, chars?)
```

- `s` (`string`): String to strip.
- `chars` (`string?`): Characters to strip (default: whitespace).
- **Returns:** `string`

---

## join

**Join array of strings with delimiter.**

```lua
NASStrings.join(delim, strings)
```

- `delim` (`string`): Delimiter.
- `strings` (`table<string>`): Array of strings.
- **Returns:** `string`

---

## startswith

**Check if string starts with substring.**

```lua
NASStrings.startswith(s1, s2)
```

- `s1` (`string`): String to check.
- `s2` (`string`): Prefix.
- **Returns:** `boolean`

---

## endswith

**Check if string ends with substring.**

```lua
NASStrings.endswith(s1, s2)
```

- `s1` (`string`): String to check.
- `s2` (`string`): Suffix.
- **Returns:** `boolean`

---

## find

**Find first occurrence of substring.**

```lua
NASStrings.find(s1, s2, start?, stop?)
```

- `s1` (`string`): String to search.
- `s2` (`string`): Substring.
- `start` (`integer?`): Start index (default: 1).
- `stop` (`integer?`): Stop index (default: -1).
- **Returns:** `integer` Index or -1.

---

## rfind

**Find last occurrence of substring.**

```lua
NASStrings.rfind(s1, s2, start?, stop?)
```

- `s1` (`string`): String to search.
- `s2` (`string`): Substring.
- `start` (`integer?`): Start index (default: 1).
- `stop` (`integer?`): Stop index (default: -1).
- **Returns:** `integer` Index or -1.

---

## index

**Like find, but errors if not found.**

```lua
NASStrings.index(s1, s2, start, stop)
```

- `s1` (`string`): String to search.
- `s2` (`string`): Substring.
- `start` (`integer`): Start index.
- `stop` (`integer`): Stop index.
- **Returns:** `integer` Index.

---

## rindex

**Like rfind, but errors if not found.**

```lua
NASStrings.rindex(s1, s2, start, stop)
```

- `s1` (`string`): String to search.
- `s2` (`string`): Substring.
- `start` (`integer`): Start index.
- `stop` (`integer`): Stop index.
- **Returns:** `integer` Index.

---

## count

**Count occurrences of pattern in string.**

```lua
NASStrings.count(s, find)
```

- `s` (`string`): String to search.
- `find` (`string`): Pattern to count.
- **Returns:** `integer` Count.

---

## replace

**Replace first n occurrences of pattern with replacement.**

```lua
NASStrings.replace(s, find, repl, n)
```

- `s` (`string`): String to search.
- `find` (`string`): Pattern to replace.
- `repl` (`string`): Replacement string.
- `n` (`integer?`): Max replacements.
- **Returns:** `string, integer` Result and number replaced.

---

## expandtabs

**Replace tabs with spaces.**

```lua
NASStrings.expandtabs(s, tabs?)
```

- `s` (`string`): String to expand.
- `tabs` (`integer?`): Number of spaces per tab (default: 4).
- **Returns:** `string, integer` Result and number replaced.

---

## with

**Read file content, line by line or as raw, applying a callback.**

```lua
NASStrings.with(file_name, mode?, executor?, file_opt?)
```

- `file_name` (`string`): File name.
- `mode` (`string?`): "lines" or "raw" (default: "raw").
- `executor` (`function?`): Callback function.
- `file_opt` (`string?`): File open mode (default: "r").
- **Returns:** `any` Result of executor.

---

## Usage Example

```lua
local strings = require("nas-utils.strings")

print(strings.capitalize("hello world")) -- "Hello world"
print(strings.split("a,b,c", ",")) -- {"a", "b", "c"}
print(strings.startswith("foobar", "foo")) -- true
print(strings.strip("  hello  ")) -- "hello"
```

---

## License

MIT License.  
Copyright (c) 2025 Net Applied Solutions, LLC.  
All rights reserved.
    
See [LICENSE](./LICENSE) for details.
