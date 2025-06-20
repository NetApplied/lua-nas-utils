-- test_utils_nas_crypto.lua

local lu = require "luaunit"
local nas_crypto = require "nas-utils.crypto"

Test_NASCrypto = {}
Test_NASCrypto._AUTHORS = "Michael Stephan"
Test_NASCrypto._VERSION = "0.3.2-1"

function Test_NASCrypto.test_base64encode()
  -- Standard Base64 encoding
  local data = "hello world"
  local encoded = nas_crypto.base64encode(data)
  lu.assertEquals(encoded, "aGVsbG8gd29ybGQ=")

  -- URL-safe Base64 encoding
  local encoded_url_safe = nas_crypto.base64encode(data, true)
  lu.assertEquals(encoded_url_safe, "aGVsbG8gd29ybGQ")

  -- Nil input
  lu.assertError(nas_crypto.base64encode, nil)
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
  lu.assertError(nas_crypto.base64decode, nil)

  -- Round-trip encoding and decoding
  local original_data = "hello world"
  local encoded_standard = nas_crypto.base64encode(original_data) or ""
  local decoded_standard = nas_crypto.base64decode(encoded_standard)
  lu.assertEquals(decoded_standard, original_data)

  local encoded_url_safe = nas_crypto.base64encode(original_data, true) or ""
  local decoded_url_safe = nas_crypto.base64decode(encoded_url_safe, true)
  lu.assertEquals(decoded_url_safe, original_data)
end

function Test_NASCrypto.test_get_random_hex()
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

function Test_NASCrypto.test_exec_popen()
  local s = nas_crypto._exec_popen("echo hello")
  lu.assertEquals(s, "hello")

  -- test keeping multi-line output
  s = nas_crypto._exec_popen("echo 'hello\nworld'")
  lu.assertEquals(s, "helloworld")

  s = nas_crypto._exec_popen("echo 'hello\nworld'", true)
  lu.assertEquals(s, "hello\nworld")
end

function Test_NASCrypto.test_kdf_derive()
  local kdf_opts = {
    type = "pbkdf2",
    md = "sha256",
    outlen = 32,
    pass = "password",
    salt = "salty",
    iter = 1000
  }
  local key_bytes = nas_crypto.kdf_derive(kdf_opts)
  lu.assertEquals(#key_bytes, 32)
  local key_hex = nas_crypto.kdf_derive(kdf_opts, true)
  lu.assertEquals(#key_hex, 64)
end

function Test_NASCrypto.test_hmac_hash()
  local secret = "key"
  local data = "The quick brown fox"
  local digest = nas_crypto.hmac_hash("sha256", secret, data)
  lu.assertIsString(digest)
  lu.assertEquals(#digest, 32)
  -- Changing secret or data changes digest
  local digest2 = nas_crypto.hmac_hash("sha256", "key2", data)
  lu.assertNotEquals(digest, digest2)
end

function Test_NASCrypto.test_encrypt_decrypt()
  -- AES-256-CBC example (using luaossl cipher enum style)
  local cipher_type = {
    name = "aes-256-cbc",
    key_length = 32,
    iv_length = 16,
    has_tag = false
  }
  local key = string.rep("k", 32)
  local iv = string.rep("i", 16)
  local data = "Secret message!"
  local ok, enc = nas_crypto.encrypt(cipher_type, data, key, iv)
  lu.assertTrue(ok)
  lu.assertIsTable(enc)
  lu.assertEquals(#enc.iv, 16)
  lu.assertIsString(enc.encrypted_data)
  lu.assertNil(enc.tag)

  local ok2, dec = nas_crypto.decrypt(cipher_type, enc.encrypted_data, key, enc.iv)
  lu.assertTrue(ok2)
  lu.assertEquals(dec, data)
end

function Test_NASCrypto.test_encrypt_decrypt_gcm()
  -- AES-128-GCM example
  local cipher_type = {
    name = "aes-128-gcm",
    key_length = 16,
    iv_length = 12,
    has_tag = true
  }
  local key = string.rep("A", 16)
  local iv = string.rep("B", 12)
  local data = "GCM mode message"
  local ok, enc = nas_crypto.encrypt(cipher_type, data, key, iv)
  lu.assertTrue(ok)
  lu.assertIsTable(enc)
  lu.assertEquals(#enc.iv, 12)
  lu.assertIsString(enc.encrypted_data)
  lu.assertIsString(enc.tag)
  lu.assertEquals(#enc.tag, 16)

  local ok2, dec = nas_crypto.decrypt(cipher_type, enc.encrypted_data, key, enc.iv, enc.tag)
  lu.assertTrue(ok2)
  lu.assertEquals(dec, data)
end

function Test_NASCrypto.test_encrypt_errors()
  local cipher_type = { name = "aes-128-cbc", key_length = 16, iv_length = 16, has_tag = false }
  local key = "short"
  local iv = "short"
  local data = "data"
  -- These should error due to short key/iv, so use assertError
  lu.assertError(nas_crypto.encrypt, cipher_type, data, key, iv)
---@diagnostic disable-next-line: param-type-mismatch
  lu.assertFalse(select(1, nas_crypto.encrypt("notatable", data, key, iv)))
end

function Test_NASCrypto.test_decrypt_errors()
  local cipher_type = { name = "aes-128-cbc", key_length = 16, iv_length = 16, has_tag = false }
  local key = "short"
  local iv = "short"
  local enc = "enc"
  lu.assertFalse(select(1, nas_crypto.decrypt(cipher_type, enc, key, iv)))
---@diagnostic disable-next-line: param-type-mismatch
  lu.assertFalse(select(1, nas_crypto.decrypt("notatable", enc, key, iv)))
  local gcm_type = { name = "aes-128-gcm", key_length = 16, iv_length = 12, has_tag = true }
  lu.assertFalse(select(1, nas_crypto.decrypt(gcm_type, enc, key, iv)))
end

function Test_NASCrypto.test_get_random_bytes()
  local b1 = nas_crypto.get_random_bytes(16)
  local b2 = nas_crypto.get_random_bytes(16)
  lu.assertIsString(b1)
  lu.assertEquals(#b1, 16)
  lu.assertNotEquals(b1, b2)
  lu.assertError(nas_crypto.get_random_bytes, "notanumber")
end

function Test_NASCrypto.test_hash_password()
  local pw = "mysecretpw"
  local salt = nas_crypto.get_random_bytes(16)
  local hash = nas_crypto.hash_password(pw, salt)
  lu.assertIsString(hash)
  lu.assertStrContains(hash, "pbkdf2_sha512$")
  lu.assertError(nas_crypto.hash_password, "short", salt)
  lu.assertError(nas_crypto.hash_password, pw, 12345)
end

function Test_NASCrypto.test_hash_password_verify()
  local pw = "mysecretpw"
  local salt = nas_crypto.get_random_bytes(16)
  local hash = nas_crypto.hash_password(pw, salt)
  lu.assertTrue(nas_crypto.hash_password_verify(pw, hash))
  lu.assertFalse(nas_crypto.hash_password_verify("wrongpass", hash))
  lu.assertError(nas_crypto.hash_password_verify, pw, "badformat")
end

function Test_NASCrypto.test_bin2hex()
  -- Lowercase and uppercase
  local bytes = "\x01\xab\xfe"
  lu.assertEquals(nas_crypto.bin2hex(bytes), "01ABFE")
  lu.assertEquals(nas_crypto.bin2hex(bytes, false), "01abfe")
  -- Empty string
  lu.assertEquals(nas_crypto.bin2hex(""), "")
end

function Test_NASCrypto.test_hex2bin()
  -- Standard hex
  lu.assertEquals(nas_crypto.hex2bin("01ABFE"), "\x01\xAB\xFE")
  lu.assertEquals(nas_crypto.hex2bin("01abfe"), "\x01\xAB\xFE")
  -- With separators
  lu.assertEquals(nas_crypto.hex2bin("01:ab-fe"), "\x01\xAB\xFE")
  lu.assertEquals(nas_crypto.hex2bin("01 ab fe"), "\x01\xAB\xFE")
  -- Empty string
  lu.assertEquals(nas_crypto.hex2bin(""), "")
end

function Test_NASCrypto.test_unixtime_milliseconds()
  local t1 = nas_crypto.unixtime_milliseconds()
  lu.assertIsNumber(t1)
  -- Should be close to os.time() * 1000
  local t2 = os.time() * 1000
  lu.assertTrue(math.abs(t1 - t2) < 10000) -- within 10 seconds
  -- Should increase over time
  local socket = require("socket") -- luasocket
  socket.sleep(0.01)
  local t3 = nas_crypto.unixtime_milliseconds()
  lu.assertTrue(t3 > t1)
end

os.exit(lu.LuaUnit.run())
