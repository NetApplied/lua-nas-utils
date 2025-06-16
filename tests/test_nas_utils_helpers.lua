-- test_utils_nas_helpers.lua
-- require "setup"
local lu = require "luaunit"
local nas_helper = require "nas-utils.helpers"

Test_NASHelper = {}
Test_NASHelper._Authors = "Michael Stephan"
Test_NASHelper._Version = "250614"

function Test_NASHelper.test_split_string()
  -- ARRANGE input string with delimiter of space
  local input_str = "hello world "
  local delimiter = ' '

  local s = nas_helper.split_string(input_str, delimiter)
  lu.assertEquals(s, { "hello", "world" })
end

function Test_NASHelper.test_unixtime_milliseconds()
  local unix_time = nas_helper.unixtime_milliseconds()
  lu.assertTrue(unix_time > os.time() * 1000)
end

function Test_NASHelper.test_roundFP()
  local v = nas_helper.roundFP(1.23456789, 0)
  lu.assertEquals(v, 1)

  -- test error if value is not a number
  lu.assertError(nas_helper.roundFP, "1.23456789", 0)

  v = nas_helper.roundFP(1.53456789, 0)
  lu.assertEquals(v, 2)

  v = nas_helper.roundFP(1.53456789, 0, false)
  lu.assertEquals(v, 1)

  v = nas_helper.roundFP(1.25456789, 1)
  lu.assertEquals(v, 1.3)

  v = nas_helper.roundFP(1.25456789, 1, false)
  lu.assertEquals(v, 1.2)

  v = nas_helper.roundFP(1.25456789, 4, false)
  lu.assertEquals(v, 1.2545)

  v = nas_helper.roundFP(1.25456789, 4, true)
  lu.assertEquals(v, 1.2546)

  v = nas_helper.roundFP(1.65, 1, true)
  lu.assertEquals(v, 1.7)

  v = nas_helper.roundFP(1.65, 1, false)
  lu.assertEquals(v, 1.6)
end

function Test_NASHelper.test_wait()
  local time_buffer_ms = 100

  ---@param wait_ms number
  ---@return number
  local function timed_wait_diff(wait_ms)
    local t1, t2, diff
    t1 = nas_helper.unixtime_milliseconds()
    nas_helper.wait(wait_ms)
    t2 = nas_helper.unixtime_milliseconds()
    diff = math.abs(t2 - t1 - wait_ms)
    print(t2, t1, wait_ms, diff)
    return diff
  end

  lu.assertTrue(timed_wait_diff(1) < time_buffer_ms)
  lu.assertTrue(timed_wait_diff(10) < time_buffer_ms)
  lu.assertTrue(timed_wait_diff(100) < time_buffer_ms)
  lu.assertTrue(timed_wait_diff(500) < time_buffer_ms)
  lu.assertTrue(timed_wait_diff(1000) < time_buffer_ms)
  lu.assertTrue(timed_wait_diff(5000) < time_buffer_ms)
end

function Test_NASHelper.test__exec_popen()
  local s = nas_helper._exec_popen("echo hello")
  lu.assertEquals(s, "hello")

  -- test keeping multi-line output
  s = nas_helper._exec_popen("echo 'hello\nworld'")
  lu.assertEquals(s, "helloworld")

  s = nas_helper._exec_popen("echo 'hello\nworld'", true)
  lu.assertEquals(s, "hello\nworld")
end

function Test_NASHelper.test_clone_function()
  -- Test upvalue of a function
  local test_var = "Value"

  local f = function()
    return test_var
  end
  local result = f()
  lu.assertEquals(f(), "Value")

  -- Now serialize/deserialize the function
  -- and check that upvalue is not retained
  local f2 = loadstring(string.dump(f))
  result = ""
  if f2 then result = f2() end
  lu.assertIsNil(result)

  -- clone_object retains upvalue
  f2 = nas_helper.clone_function(f)
  result = f2()
  lu.assertEquals(result, "Value")

end

function Test_NASHelper.test_trim()
  lu.assertEquals(nas_helper.trim("\r\n  test  \r\n"), "test")
  lu.assertEquals(nas_helper.trim("  test  "), "test")
  lu.assertEquals(nas_helper.trim("*  test  *", " *"), "test")
  lu.assertEquals(nas_helper.trim("[]~  test  ", "[]~ "), "test")
  lu.assertEquals(nas_helper.trim("a+b  test  a+b", "a+b "), "test")
  lu.assertEquals(nas_helper.trim("abc+a", "a+b"), "c")
  lu.assertEquals(nas_helper.trim("%test%", "%"), "test")
end

function Test_NASHelper.test_ltrim()
  lu.assertEquals(nas_helper.ltrim("\r\n  test  "), "test  ")
  lu.assertEquals(nas_helper.ltrim("  test  "), "test  ")
  lu.assertEquals(nas_helper.ltrim("*  test  *", " *"), "test  *")
  lu.assertEquals(nas_helper.ltrim("[]~  test  ", "[]~ "), "test  ")
  lu.assertEquals(nas_helper.ltrim("a+b  test  a+b", "a+b "), "test  a+b")
  lu.assertEquals(nas_helper.ltrim("abc+a", "a+b"), "c+a")
  lu.assertEquals(nas_helper.ltrim("%Hello", "%"), "Hello")
end

function Test_NASHelper.test_rtrim()
  lu.assertEquals(nas_helper.rtrim("  test \r\n  "), "  test")
  lu.assertEquals(nas_helper.rtrim("  test  "), "  test")
  lu.assertEquals(nas_helper.rtrim("*  test  *", " *"), "*  test")
  lu.assertEquals(nas_helper.rtrim("[]~  test  []~", "[]~ "), "[]~  test")
  lu.assertEquals(nas_helper.rtrim("a+b  test  a+b", "a+b "), "a+b  test")
  lu.assertEquals(nas_helper.rtrim("abc+a", "a+b"), "abc")
  lu.assertEquals(nas_helper.rtrim("Hello%", "%"), "Hello")
end

function Test_NASHelper.test_dict_size()
  lu.assertEquals(nas_helper.dict_size({}), 0)
  -- lu.assertEquals(nas_helpers.dict_size(""), 0)
  lu.assertEquals(nas_helper.dict_size({ a = "b" }), 1)
  lu.assertEquals(nas_helper.dict_size({ "a" }), 1)
end

function Test_NASHelper.test_dict_is_empty()
  lu.assertFalse(nas_helper.dict_is_empty({ "a" }))
  lu.assertTrue(nas_helper.dict_is_empty({}))
  lu.assertError(nas_helper.dict_is_empty, "string_value")
end

function Test_NASHelper.test_dict_sort()
  lu.assertError(nas_helper.dict_sort, "string_value")
  lu.assertError(nas_helper.dict_sort, { "can", "not", "be", "a", "list" })

  -- test sort by key
  lu.assertEquals(
    nas_helper.dict_sort({ c = 2, a = 3, b = 1 }),
    { { "a", 3 }, { "b", 1 }, { "c", 2 } }
  )

  -- test sort by value
  lu.assertEquals(
    nas_helper.dict_sort({ c = 2, a = 3, b = 1 }, true),
    { { "b", 1 }, { "c", 2 }, { "a", 3 } }
  )

  -- test sort by value with reverse sort
  lu.assertEquals(
    nas_helper.dict_sort({ c = 2, a = 3, b = 1 }, true, true),
    { { "a", 3 }, { "c", 2 }, { "b", 1 } }
  )

  
  local dict, result_dict
  dict = {
    c = "Tom",
    a = "Steve",
    B = "billy",
    x = 10,
    d = 4.53,
    g = 100,
    f = 200,
    s = 1.53
  }

  -- test case-insensitive sort by key
  result_dict = {
    { "a", "Steve" },
    { "B", "billy" },
    { "c", "Tom" },
    { "d", 4.53 },
    { "f", 200 },
    { "g", 100 },
    { "s", 1.53 },
    { "x", 10 }
  }
  lu.assertEquals(nas_helper.dict_sort(dict, false, false, false), result_dict)

  -- test case-insensitive sort by value, reverse order
  result_dict = {
    { "c", "Tom" },
    { "a", "Steve" },
    { "B", "billy" },
    { "f", 200 },
    { "g", 100 },
    { "x", 10 },
    { "d", 4.53 },
    { "s", 1.53 },
  }
  lu.assertEquals(nas_helper.dict_sort(dict, true, true, false), result_dict)

end


function Test_NASHelper.test_table_is_list()
  lu.assertTrue(nas_helper.table_is_list({ 1, 2, 3 }))
  lu.assertFalse(nas_helper.table_is_list({ a = "a" }))
  lu.assertFalse(nas_helper.table_is_list({}))
end

function Test_NASHelper.test_table_is_dict()
  lu.assertFalse(nas_helper.table_is_dict({ 1, 2, 3 }))
  lu.assertTrue(nas_helper.table_is_dict({ a = "a" }))
  lu.assertTrue(nas_helper.table_is_dict({}))
end

os.exit(lu.LuaUnit.run())
