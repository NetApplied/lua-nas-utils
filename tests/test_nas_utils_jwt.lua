---@diagnostic disable: undefined-field
-- test_nas_utils_jwt.lua

local lu = require "luaunit"
local nas_jwt = require "nas-utils.jwt"

Test_NASJwt = {}
Test_NASJwt._AUTHORS = "Michael Stephan"
Test_NASJwt._VERSION = "0.3.2-1"

function Test_NASJwt.test_jwt_encode_decode_basic()
  local payload = { user = "alice", role = "admin" }
  local secret = "supersecret"
  local token = nas_jwt.encode(payload, secret)
  lu.assertIsString(token)

  local ok, decoded = nas_jwt.decode(token, secret)
  lu.assertTrue(ok)
  lu.assertIsTable(decoded)
  lu.assertEquals(decoded.user, "alice")
  lu.assertEquals(decoded.role, "admin")
end

function Test_NASJwt.test_jwt_encode_decode_hs512()
  local payload = { user = "bob" }
  local secret = "anothersecret"
  local token = nas_jwt.encode(payload, secret, "HS512")
  lu.assertIsString(token)

  local ok, decoded = nas_jwt.decode(token, secret)
  lu.assertTrue(ok)
  lu.assertEquals(decoded.user, "bob")
end

function Test_NASJwt.test_jwt_invalid_secret()
  local payload = { foo = "bar" }
  local secret = "secret1"
  local token = nas_jwt.encode(payload, secret)
  local ok, err = nas_jwt.decode(token, "wrongsecret")
  lu.assertFalse(ok)
  lu.assertStrContains(err, "Invalid token signature")
end

function Test_NASJwt.test_jwt_invalid_token_format()
  local ok, err = nas_jwt.decode("not.a.jwt", "secret")
  lu.assertFalse(ok)
  lu.assertStrContains(err, "Invalid header")
end

function Test_NASJwt.test_jwt_invalid_algorithm()
  local base64encode = require("nas-utils.crypto").base64encode
  local base64decode = require("nas-utils.crypto").base64decode
  local payload = { foo = "bar" }
  local secret = "secret"
  local token = nas_jwt.encode(payload, secret)
  -- Tamper with header to use unsupported alg
  local parts = {}
  for part in string.gmatch(token, "([^%.]+)") do table.insert(parts, part) end
  local header = require("cjson").decode(base64decode(parts[1], true) or "{}")
  header.alg = "HS999"
  parts[1] = base64encode(require("cjson").encode(header), true)
  local tampered = table.concat(parts, ".")
  local ok, err = nas_jwt.decode(tampered, secret)
  lu.assertFalse(ok)
  lu.assertStrContains(err, "Invalid algorithm")
end

function Test_NASJwt.test_jwt_expired()
  local payload = { foo = "bar", exp = os.time() - 10 }
  local secret = "secret"
  local token = nas_jwt.encode(payload, secret)
  local ok, err = nas_jwt.decode(token, secret)
  lu.assertFalse(ok)
  lu.assertStrContains(err, "Token has expired")
end

function Test_NASJwt.test_jwt_no_exp_check()
  local payload = { foo = "bar", exp = os.time() - 10 }
  local secret = "secret"
  local token = nas_jwt.encode(payload, secret)
  local ok, decoded = nas_jwt.decode(token, secret, false)
  lu.assertTrue(ok)
  lu.assertEquals(decoded.foo, "bar")
end

function Test_NASJwt.test_jwt_claim_defaults()
  local payload = {}
  local secret = "secret"
  local token = nas_jwt.encode(payload, secret)
  local ok, decoded = nas_jwt.decode(token, secret)
  lu.assertTrue(ok)
  lu.assertIsNumber(decoded.iat)
  lu.assertIsNumber(decoded.nbf)
  lu.assertIsNumber(decoded.exp)
  lu.assertEquals(decoded.sub, "anonymous")
  lu.assertEquals(decoded.iss, "https://default.issuer.example.com")
  lu.assertEquals(decoded.aud, "https://default.audience.example.com")
end

function Test_NASJwt.test_jwt_encode_errors()
  lu.assertError(nas_jwt.encode, nil, "secret")
  lu.assertError(nas_jwt.encode, {}, nil)
end

os.exit(lu.LuaUnit.run())
