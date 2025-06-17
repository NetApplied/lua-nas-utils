-- nas-utils.init.lua
-- TODO: Move enumerations into init.lua

local modules               = {}

modules._AUTHORS            = "Michael Stephan"
modules._VERSION            = "0.3.2-1"
modules._LICENSE            = "MIT License"
modules._COPYRIGHT          = "Copyright (c) 2025 NetApplied Solutions"
modules._HOMEPAGE           = "https://github.com/NetApplied/lua-nas-utils"
modules._DESCRIPTION        = "A collection of Lua utilities for NAS systems."

modules.helpers             = require("nas-utils.helpers")
modules.crypto              = require("nas-utils.crypto")
modules.strings             = require("nas-utils.strings")
modules.logger_rolling_file = require("nas-utils.logger_rolling_file")


-----------------------
-- Logging Enumerations
-----------------------
---@enum Enum_LogLevel
modules.LogLevel  = {
    DEBUG = "DEBUG",
    INFO = "INFO",
    WARN = "WARN",
    ERROR = "ERROR",
    FATAL = "FATAL"
}


----------------------
-- Crypto Enumerations
----------------------

-- `Enum_CipherType` enum is available from `require("nas-utils").CipherType`
---@alias Enum_CipherType {name: string, key_length: number, iv_length: number, 
---has_tag: boolean}
---
-- @enum tag does not work with complex table, use @alias instead
-- ---@enum Enum_CipherType
modules.CipherType = {
  AES_128_CBC = {
    name = 'aes-128-cbc',
    key_length = 16,
    iv_length = 16,
    has_tag = false
  },
  AES_192_CBC = {
    name = 'aes-192-cbc',
    key_length = 24,
    iv_length = 16,
    has_tag = false
  },
  AES_256_CBC = {
    name = 'aes-256-cbc',
    key_length = 32,
    iv_length = 16,
    has_tag = false
  },
  DES_CBC = {
    name = 'des-cbc',
    key_length = 8,
    iv_length = 8,
    has_tag = false
  },
  DES_EDE3_CBC = {
    name = 'des-ede3-cbc',
    key_length = 24,
    iv_length = 8,
    has_tag = false
  },
  BF_CBC = {
    name = 'bf-cbc',
    key_length = 16,
    iv_length = 8,
    has_tag = false
  },
  BF_OFB = {
    name = 'bf-ofb',
    key_length = 16,
    iv_length = 8,
    has_tag = false
  },
  RC4 = {
    name = 'rc4',
    key_length = 16,
    iv_length = 0,
    has_tag = false
  },
  CAMELLIA_128_CBC = {
    name = 'camellia-128-cbc',
    key_length = 16,
    iv_length = 16,
    has_tag = false
  },
  CAMELLIA_192_CBC = {
    name = 'camellia-192-cbc',
    key_length = 24,
    iv_length = 16,
    has_tag = false
  },
  CAMELLIA_256_CBC = {
    name = 'camellia-256-cbc',
    key_length = 32,
    iv_length = 16,
    has_tag = false
  },
  AES_128_GCM = {
    name = 'aes-128-gcm',
    key_length = 16,
    iv_length = 12,
    has_tag = true
  },
  AES_192_GCM = {
    name = 'aes-192-gcm',
    key_length = 24,
    iv_length = 12,
    has_tag = true
  },
  AES_256_GCM = {
    name = 'aes-256-gcm',
    key_length = 32,
    iv_length = 12,
    has_tag = true
  }
}

---@enum Enum_DigestType
modules.DigestType = {
  BLAKE2B512 = "blake2b512",
  BLAKE2S256 = "blake2s256",
  MD4 = "md4",
  MD5 = "md5",
  MDC2 = "mdc2",
  RMD160 = "rmd160",
  SHA1 = "sha1",
  SHA224 = "sha224",
  SHA256 = "sha256",
  SHA384 = "sha384",
  SHA512 = "sha512",
  SHA512_224 = "sha512-224",
  SHA512_256 = "sha512-256",
  SHA3_224 = "sha3-224",
  SHA3_256 = "sha3-256",
  SHA3_384 = "sha3-384",
  SHA3_512 = "sha3-512",
  SHAKE128 = "shake128",
  SHAKE256 = "shake256",
  SM3 = "sm3",
}


-- Function that recieves a cipher name and returns corresponding Enum_CipherType table
---@param cipher_name string The name of the role to retrieve.
---@return Enum_CipherType? cipher The corresponding cipher table or nil if not found
function modules.get_cipher_by_name(cipher_name)
  for _, cipher_type in ipairs(modules.CipherType) do
    if string.upper(cipher_type.name) == string.upper(cipher_name) then
      return cipher_type
    end
  end
  return nil
end

return modules

--[[ -- don't load modules dynamically, so LLS can
modules.path = "nas-utils."
-- list of modules
local module_names = {
    "crypto",
    "helpers",
    "strings",
    "logger_rolling_file",
}
for _, name in ipairs(module_names) do
    modules[name] = require(modules.path .. name)
end
-- ]]
