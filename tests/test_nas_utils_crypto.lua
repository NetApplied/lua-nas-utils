-- test_utils_nas_crypto.lua
-- require "setup"

local lu = require "luaunit"
local nas_crypto = require "nas-utils.crypto"

Test_NASCrypto = {}
Test_NASCrypto._Authors = "Michael Stephan"
Test_NASCrypto._Version = "250614"

function Test_NASCrypto.test_base64encode()
  -- Standard Base64 encoding
  local data = "hello world"
  local encoded = nas_crypto.base64encode(data)
  lu.assertEquals(encoded, "aGVsbG8gd29ybGQ=")

  -- URL-safe Base64 encoding
  local encoded_url_safe = nas_crypto.base64encode(data, true)
  lu.assertEquals(encoded_url_safe, "aGVsbG8gd29ybGQ")

  -- Nil input
  ---@diagnostic disable-next-line: param-type-mismatch
  local encoded_nil = nas_crypto.base64encode(nil)
  lu.assertIsNil(encoded_nil)
end

function Test_NASCrypto.test_base64decode()
  -- Standard Base64 decoding
  local data = "aGVsbG8gd29ybGQ="
  local decoded = nas_crypto.base64decode(data)
  lu.assertEquals(decoded, "hello world")

  -- URL-safe Base64 decoding
  local data_url_safe = "aGVsbG8gd29ybGQ"
  local decoded_url_safe = nas_crypto.base64decode(data_url_safe, true)
  lu.assertEquals(decoded_url_safe, "hello world")

  -- Nil input
  ---@diagnostic disable-next-line: param-type-mismatch
  local decoded_nil = nas_crypto.base64decode(nil)
  lu.assertIsNil(decoded_nil)

  -- Round-trip encoding and decoding
  local original_data = "hello world"
  local encoded_standard = nas_crypto.base64encode(original_data) or ""
  local decoded_standard = nas_crypto.base64decode(encoded_standard)
  lu.assertEquals(decoded_standard, original_data)

  local encoded_url_safe = nas_crypto.base64encode(original_data, true) or ""
  local decoded_url_safe = nas_crypto.base64decode(encoded_url_safe, true)
  lu.assertEquals(decoded_url_safe, original_data)
end

function Test_NASCrypto.test_crypto_get_random_hex()
  local hex = nas_crypto.get_random_hex(32)
  lu.assertEquals(#hex, 64)

  local hex2 = nas_crypto.get_random_hex(8)
  lu.assertEquals(#hex2, 16)

  hex = nas_crypto.get_random_hex()
  lu.assertEquals(#hex, 32)

  hex = nas_crypto.get_random_hex()
  hex2 = nas_crypto.get_random_hex()
  lu.assertNotEquals(hex, hex2)
end

function Test_NASCrypto.test_crypto_hash_password()
  -- test error on empty password
  local pwh
  lu.assertError(nas_crypto.hash_password)

  -- test error on password with no salt
  lu.assertError(nas_crypto.hash_password, "password")

  -- test error on password with less than 8 characters
  lu.assertError(nas_crypto.hash_password, "1234567", "salt")

  -- test error on password that is not a string
  lu.assertError(nas_crypto.hash_password, 1234567, "salt")

  -- test hash password with salt
  pwh = nas_crypto.hash_password("password", "salt")
  lu.assertIsString(pwh)
end

function Test_NASCrypto.test_crypto_hash_password_verify()
  local pwh, vpwh

  -- ARRANGE password hash
  pwh = nas_crypto.hash_password("password", "salt")

  -- test error on no arguments
  lu.assertError(nas_crypto.hash_password_verify)

  -- test error on password with less than 8 characters
  lu.assertError(nas_crypto.hash_password_verify, "1234567", pwh, "salt")


  -- test password and hashed password reversed arguments
  vpwh = nas_crypto.hash_password_verify(pwh, "password", "salt")
  lu.assertFalse(vpwh)

  -- test hash verifies correctly
  vpwh = nas_crypto.hash_password_verify("password", pwh, "salt")
  lu.assertTrue(vpwh)
end

function Test_NASCrypto.test_crypto_exec_popen()
  local s = nas_crypto._exec_popen("echo hello")
  lu.assertEquals(s, "hello")

  -- test keeping multi-line output
  s = nas_crypto._exec_popen("echo 'hello\nworld'")
  lu.assertEquals(s, "helloworld")

  s = nas_crypto._exec_popen("echo 'hello\nworld'", true)
  lu.assertEquals(s, "hello\nworld")
end

os.exit(lu.LuaUnit.run())
