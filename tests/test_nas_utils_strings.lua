---@diagnostic disable: need-check-nil
-- test_nas_utils_strings.lua

local lu = require "luaunit"
local nas_strings = require "nas-utils.strings"

Test_NASStrings = {}
Test_NASStrings._Authors = "Michael Stephan"
Test_NASStrings._Version = "250614"

function Test_NASStrings:test_split()
    local ret = nas_strings.split("hello lua language")
    lu.assertEquals(#ret, 3)
    lu.assertEquals(ret[1], "hello")
    lu.assertEquals(ret[2], "lua")
    lu.assertEquals(ret[3], "language")

    ret = nas_strings.split("hello lua language lua language")
    lu.assertEquals(#ret, 5)
    lu.assertEquals(ret[1], "hello")
    lu.assertEquals(ret[2], "lua")
    lu.assertEquals(ret[3], "language")
    lu.assertEquals(ret[4], "lua")
    lu.assertEquals(ret[5], "language")

    ret = nas_strings.split("Node 0, zone DMA 1 0 0 1 2 1 1 0 1 1 3")
    lu.assertEquals(#ret, 15)
end

function Test_NASStrings:test_split_delimiter()
    local ret = nas_strings.split("hello*lua *language", "*")
    lu.assertEquals(#ret, 3)
    lu.assertEquals(ret[1], "hello")
    lu.assertEquals(ret[2], "lua ")
    lu.assertEquals(ret[3], "language")
end

function Test_NASStrings:test_rsplit()
    local largeStr = string.rep("a", 1024 * 1024) .. " " .. "b" .. " " .. "c"
    local ret = nas_strings.rsplit(largeStr, nil, 2)
    lu.assertEquals(#ret, 3)
    lu.assertEquals(ret[2], "b")
    lu.assertEquals(ret[3], "c")

    ret = nas_strings.rsplit(largeStr, nil, 1)
    lu.assertEquals(#ret, 2)
    lu.assertEquals(ret[2], "c")
    lu.assertStrContains(string.sub(ret[1], -4, -1), "a b")

    largeStr = string.rep("a", 1024 * 1024) .. "del" .. "b" .. "del" .. "c"
    ret = nas_strings.rsplit(largeStr, "del", 2)
    lu.assertEquals(#ret, 3)
    lu.assertEquals(ret[2], "b")
    lu.assertEquals(ret[3], "c")

    ret = nas_strings.rsplit(largeStr, "del", 1)
    lu.assertEquals(#ret, 2)
    lu.assertEquals(ret[2], "c")
    lu.assertStrContains(string.sub(ret[1], -5, -1), "adelb")

    -- Test short string
    local shortStr = "a" .. " " .. "b" .. " " .. "c"
    ret = nas_strings.rsplit(shortStr, nil, 2)
    lu.assertEquals(#ret, 3)
    lu.assertEquals(ret[2], "b")
    lu.assertEquals(ret[3], "c")
end

function Test_NASStrings:test_split_multi_string()
    local ret = nas_strings.split("hello*lua *language", "*l")
    lu.assertEquals(#ret, 3)
    lu.assertEquals(ret[1], "hello")
    lu.assertEquals(ret[2], "ua ")
    lu.assertEquals(ret[3], "anguage")
end

function Test_NASStrings:test_partition()
    local ret = nas_strings.partition("hello lua")
    lu.assertEquals(#ret, 3)
    lu.assertEquals(ret[1], "hello")
    lu.assertEquals(ret[2], " ")
    lu.assertEquals(ret[3], "lua")

    ret = nas_strings.partition("hello*lua", "*")
    lu.assertEquals(#ret, 3)
    lu.assertEquals(ret[1], "hello")
    lu.assertEquals(ret[2], "*")
    lu.assertEquals(ret[3], "lua")

    ret = nas_strings.partition("hello lua language")
    lu.assertEquals(#ret, 3)
    lu.assertEquals(ret[1], "hello")
    lu.assertEquals(ret[2], " ")
    lu.assertEquals(ret[3], "lua language")

    ret = nas_strings.partition("hello lua language", "lua")
    lu.assertEquals(#ret, 3)
    lu.assertEquals(ret[1], "hello ")
    lu.assertEquals(ret[2], "lua")
    lu.assertEquals(ret[3], " language")

    ret = nas_strings.partition("hello*lua")
    lu.assertNil(ret)
end

function Test_NASStrings:test_rpartition()
    local ret = nas_strings.rpartition("hello lua language")
    lu.assertNotNil(ret)
    lu.assertEquals(#ret, 3)
    lu.assertIsTable(ret)
    lu.assertEquals(ret[1], "hello lua")
    lu.assertEquals(ret[2], " ")
    lu.assertEquals(ret[3], "language")

    ret = nas_strings.rpartition("hello lua lua language", "lua")
    lu.assertEquals(ret[1], "hello lua ")
    lu.assertEquals(ret[2], "lua")
    lu.assertEquals(ret[3], " language")
end

function Test_NASStrings:test_splitlines()
    local ret = nas_strings.splitlines("hello\nlua\nlanguage")
    lu.assertEquals(ret[1], "hello")
    lu.assertEquals(ret[2], "lua")
    lu.assertEquals(ret[3], "language")
end

function Test_NASStrings:test_strip()
    lu.assertEquals(nas_strings.strip("\t hello world. \t\n"), "hello world.")
    lu.assertEquals(nas_strings.strip("**hello world**", "*"), "hello world")
    lu.assertEquals(nas_strings.strip("*?hello world*?", "*?"), "hello world")
    lu.assertEquals(nas_strings.strip("abcdefhello worldabcdef", "abcdef"), "hello world")
    lu.assertEquals(nas_strings.lstrip("abcdefhello worldabcdef", "abcdef"), "hello worldabcdef")
    lu.assertEquals(nas_strings.rstrip("abcdefhello worldabcdef", "abcdef"), "abcdefhello world")
end

function Test_NASStrings:test_join()
    local s = "abc d ef g"
    local ret = nas_strings.split(s)
    lu.assertEquals(nas_strings.join(" ", ret), s)
end

function Test_NASStrings:test_startswith_endswith()
    lu.assertTrue(nas_strings.startswith("hello world", "hello"))
    lu.assertTrue(nas_strings.endswith("hello world", "world"))
end

function Test_NASStrings:test_find()
    lu.assertEquals(nas_strings.find("hello world.", "hello"), 1)
    lu.assertEquals(nas_strings.find("hello world.", "hEllo"), -1)
end

function Test_NASStrings:test_rfind()
    lu.assertEquals(nas_strings.rfind("hello world hello.", "hello"), 12)
    lu.assertEquals(nas_strings.rfind("hello world hello.", "hEllo"), -1)

    local largeStr = string.rep("a", 1024 * 1024) .. "del" .. "b" .. "del" .. "c"
    lu.assertEquals(nas_strings.rfind(largeStr, "del"), #largeStr - 3)
end

function Test_NASStrings:test_count()
    lu.assertEquals(nas_strings.count("hello world hello.", "hello"), 2)
    lu.assertEquals(nas_strings.count("hello world hello.", "hEllo"), 0)
    lu.assertEquals(nas_strings.count("hello world hello.", " "), 2)
end

function Test_NASStrings:test_shift()
    lu.assertEquals(nas_strings.shift("abcd", 1), "dabc")
    lu.assertEquals(nas_strings.shift("abcd", -1), "bcda")
    lu.assertEquals(nas_strings.shift("abcd", -2), "cdab")
end

function Test_NASStrings:test_swapcase()
    lu.assertEquals(nas_strings.swapcase("Hello, World!"), "hELLO, wORLD!")
end

function Test_NASStrings:test_capitalize()
    lu.assertEquals(nas_strings.capitalize("hello"), "Hello")
    lu.assertEquals(nas_strings.capitalize(""), "")
    lu.assertEquals(nas_strings.capitalize("H"), "H")
end

function Test_NASStrings:test_title()
    lu.assertEquals(nas_strings.title("hello"), "Hello")
    lu.assertEquals(nas_strings.title(""), "")
    lu.assertEquals(nas_strings.title("hello world."), "Hello World.")
end

function Test_NASStrings:test_capwords()
    lu.assertEquals(nas_strings.capwords("hello world."), "Hello World.")
    lu.assertEquals(nas_strings.capwords("hello world.\nhere you are."), "Hello World.\nHere You Are.")
end

function Test_NASStrings:test_islower()
    lu.assertTrue(nas_strings.islower("hello"))
    lu.assertFalse(nas_strings.islower("Hello"))
    lu.assertTrue(nas_strings.islower("hello world!"))
end

function Test_NASStrings:test_isupper()
    lu.assertTrue(nas_strings.isupper("HELLO"))
    lu.assertFalse(nas_strings.isupper("Hello"))
    lu.assertFalse(nas_strings.isupper("Hello World"))
    lu.assertTrue(nas_strings.isupper("HELLO WORLD!"))
end

function Test_NASStrings:test_isdigit()
    lu.assertTrue(nas_strings.isdigit("1234"))
    lu.assertFalse(nas_strings.isdigit("123a"))
    lu.assertFalse(nas_strings.isdigit("123.45"))
end

function Test_NASStrings:test_ishex()
    lu.assertTrue(nas_strings.ishex("1234"))
    lu.assertTrue(nas_strings.ishex("123a"))
    lu.assertTrue(nas_strings.ishex("abcdef"))
    lu.assertTrue(nas_strings.ishex("00ABCDEF"))
    lu.assertFalse(nas_strings.ishex("123FG"))
    lu.assertFalse(nas_strings.ishex("123.45"))
end

function Test_NASStrings:test_isalnum()
    lu.assertTrue(nas_strings.isalnum("1234"))
    lu.assertTrue(nas_strings.isalnum("00ABCDEF"))
    lu.assertTrue(nas_strings.isalnum("123FG"))
    lu.assertFalse(nas_strings.isalnum("123.45"))
    lu.assertFalse(nas_strings.isalnum("123 45"))
end

function Test_NASStrings:test_istitle()
    lu.assertTrue(nas_strings.istitle("Aaa"))
    lu.assertFalse(nas_strings.istitle("aaa"))
    lu.assertFalse(nas_strings.istitle("Aaa0"))
    lu.assertTrue(nas_strings.istitle("A"))
end

function Test_NASStrings:test_isfloat()
    lu.assertFalse(nas_strings.isfloat("1234"))
    lu.assertFalse(nas_strings.isfloat("00ABCDEF"))
    lu.assertFalse(nas_strings.isfloat("123FG"))
    lu.assertTrue(nas_strings.isfloat("123.45"))
    lu.assertFalse(nas_strings.isfloat("123 45"))
end

function Test_NASStrings:test_ljust()
    lu.assertEquals(nas_strings.ljust("1234", 5), " 1234")
    lu.assertEquals(nas_strings.ljust("1234", 3), "1234")
    lu.assertEquals(nas_strings.ljust("1234", 6, "*"), "**1234")
end

function Test_NASStrings:test_rjust()
    lu.assertEquals(nas_strings.rjust("1234", 5), "1234 ")
    lu.assertEquals(nas_strings.rjust("1234", 3), "1234")
    lu.assertEquals(nas_strings.rjust("1234", 6, "*"), "1234**")
end

function Test_NASStrings:test_center()
    lu.assertEquals(nas_strings.center("1234", 5), "1234 ")
    lu.assertEquals(nas_strings.center("1234", 7), " 1234  ")
    lu.assertEquals(nas_strings.center("1234", 8), "  1234  ")
    lu.assertEquals(nas_strings.center("1234", 8, "*"), "**1234**")
end

function Test_NASStrings:test_zfill()
    lu.assertEquals(nas_strings.zfill("3.14", 6), "003.14")
end

function Test_NASStrings:test_replace()
    lu.assertEquals(nas_strings.replace("hello world.", "world", "lua"), "hello lua.")
    lu.assertEquals(nas_strings.replace("hello world world.", "world", "lua"), "hello lua lua.")
    lu.assertEquals(nas_strings.replace("hello world world.", "world", "lua", 1), "hello lua world.")
    lu.assertEquals(nas_strings.replace("hello %. %*.", "%.", "%*"), "hello %* %*.")
    lu.assertEquals(nas_strings.replace("hello %. %*.", "%.", " "), "hello   %*.")
end

function Test_NASStrings:test_expandtabs()
    lu.assertEquals(nas_strings.expandtabs("hello\tworld."), "hello    world.")
end

function Test_NASStrings:test_with()
    local file = 'test_file.txt'
    local content = "hello there!\nWhat's up?"
    local f = io.open(file, 'w')
    if not f then
        error(string.format("io.open failed opening %s file in write mode", file))
    end
    f:write(content)
    f:close()

    local withContent = nas_strings.with(file)
    lu.assertEquals(withContent, content)

    withContent = nas_strings.with(file, nil, function(s) return nas_strings.lower(s) end)
    lu.assertEquals(withContent, nas_strings.lower(content))

    local withTable = nas_strings.with(file, "lines")
    lu.assertEquals(nas_strings.join("\n", withTable), content)

    withTable = nas_strings.with(file, "lines", function(s) return nas_strings.upper(s) end)
    lu.assertEquals(nas_strings.join("\n", withTable), nas_strings.upper(content))

    os.execute('rm ' .. file)
end

os.exit(lu.LuaUnit.run())