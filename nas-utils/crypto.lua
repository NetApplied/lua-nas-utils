-- nas-utils.crypto.lua
--TODO: HMAC function for HMAC-SHA256

local NASCrypto      = {}

NASCrypto._AUTHORS   = "Michael Stephan"
NASCrypto._VERSION   = "0.3.2-1"
NASCrypto._LICENSE   = "MIT License"
NASCrypto._COPYRIGHT = "Copyright (c) 2025 NetApplied Solutions"

local socket         = require("socket") -- luasocket
local rand           = require("openssl.rand") -- luaossl
local cipher         = require("openssl.cipher") -- luaossl
local hmac           = require("openssl.hmac") -- luaossl
local replace        = require("nas-utils.strings").replace
local b64encode      = require("mime").b64
local b64decode      = require("mime").unb64


--[[
********************
*** CRYPTO UTILS ***
********************
]]

-- Base64 encoding with url safe option
---@param data string Data to encode
---@param url_safe boolean? Option to make the encoding URL-safe (default is false)
---@return string? The base64 encoded string or nil if data is nil
function NASCrypto.base64encode(data, url_safe)
  url_safe = url_safe or false
  if not data then return nil end

  -- Standard Base64 encoding
  local encoded = b64encode(data)

  if url_safe then
    -- Make it URL-safe
    encoded = string.gsub(encoded, '+', '-')
    encoded = string.gsub(encoded, '/', '_')
    encoded = string.gsub(encoded, '=', '')
  end

  return encoded
end

-- Base64 decoding with url safe option
---@param data string Data to decode
---@param url_safe boolean? Option for when data is URL-safe encoded (default is false)
---@return string? The base64 decoded string or nil if data is nil
function NASCrypto.base64decode(data, url_safe)
  url_safe = url_safe or false
  if not data then return nil end

  if url_safe then
    -- Add padding back if necessary
    while string.len(data) % 4 ~= 0 do
      data = data .. '='
    end

    -- Convert URL-safe characters back to standard Base64
    data = string.gsub(data, '-', '+')
    data = string.gsub(data, '_', '/')
  end

  -- Standard Base64 decoding
  local decoded = b64decode(data)

  return decoded
end


-- Encrypts data using the specified cipher. If cipher uses GCM mode, a tag is generated.
---@param cipher_type Enum_CipherType `Enum_CipherType` to use for encryption.
---@param data string Data to be encrypted
---@param key string Encryption key of appropriate length
---@param iv string? Initialization vector of appropriate length. Generated if not provided
---@param tag_length number? Length of the authentication tag. Max and default is 16 bytes
---@return {iv: string, encrypted_data: string, tag: string? }? encrypted_table
function NASCrypto.encrypt(cipher_type, data, key, iv, tag_length)
  tag_length = tag_length or 16 -- Default to 16 bytes if not specified

  if cipher_type == nil or data == nil or key == nil then
    error("Must provide cipher, data and key")
  end

  if type(cipher_type) ~= "table" then
    error("cipher_enum parameter must be Enum_CipherType table")
  end

  -- Ensure the key and IV are of appropriate length for the chosen cipher
  local key_length = cipher_type.key_length
  local iv_length = cipher_type.iv_length

  -- if iv not provided, generate a random one
  if iv == nil then
    if not rand.ready() then
      error("Random number generator is not properly seeded")
    end
    iv = rand.bytes(iv_length)
  end

  if #iv < iv_length then
    error("IV for " .. cipher_type.name .. " must be at least "
      .. iv_length .. " bytes")
  end

  if #key < key_length then
    error("Key for " .. cipher_type.name .. " must be at least "
      .. key_length .. " bytes")
  end

  key = string.sub(key, 1, key_length)
  iv = string.sub(iv, 1, iv_length)

  -- Create a new cipher context
  local ctx = cipher.new(cipher_type.name)
  if not ctx then
    error("Failed to create cipher context for " .. cipher_type.name)
  end

  -- Initialize the cipher for encryption
  if not ctx:encrypt(key, iv) then
    error("Failed to initialize cipher for encryption")
  end

  -- Encrypt the data
  local encrypted_data = ctx:update(data)
  encrypted_data = encrypted_data .. ctx:final()

  if not encrypted_data then return nil end

  -- get authentication tag if supported by cipher
  local tag = cipher_type.has_tag and ctx:getTag(tag_length) or nil

  return {
    iv = iv,
    encrypted_data = encrypted_data,
    tag = tag
  }
end

-- Decrypts data using the specified cipher. If cipher uses GCM, a tag must be provided.
---@param cipher_type Enum_CipherType `Enum_CipherType` to use for encryption.
---@param encrypted_data string Data to be decrypted
---@param key string Encryption key of appropriate length
---@param iv string Initialization vector of appropriate length.
---@param tag string? Optional authentication tag required if cipher uses GCM.
---@return string? Decrypted data or nil if decryption fails.
function NASCrypto.decrypt(cipher_type, encrypted_data, key, iv, tag)
  local decrypted_data = nil

  if cipher_type == nil or encrypted_data == nil or key == nil or iv == nil then
    error("Must provide cipher, encrypted_data, key and iv")
  end

  if type(cipher_type) ~= "table" then
    error("cipher_enum parameter must be Enum_CipherType table")
  end

  if cipher_type.has_tag and tag == nil then
    error("Tag is required for GCM mode")
  end

  -- Ensure the key and IV are of appropriate length for the chosen cipher
  local key_length = cipher_type.key_length
  local iv_length = cipher_type.iv_length

  if #iv < iv_length then
    error("IV for " .. cipher_type.name .. " must be at least "
      .. iv_length .. " bytes")
  end

  if #key < key_length then
    error("Key for " .. cipher_type.name .. " must be at least "
      .. key_length .. " bytes")
  end

  key = string.sub(key, 1, key_length)
  iv = string.sub(iv, 1, iv_length)

  -- Create a new cipher context
  local ctx = cipher.new(cipher_type.name)
  if not ctx then
    error("Failed to create cipher context for " .. cipher_type.name)
  end

  -- Initialize the cipher for decryption
  if not ctx:decrypt(key, iv) then
    error("Failed to initialize cipher for decryption")
  end

  if cipher_type.has_tag then
    if not ctx:setTag(tag) then
      error("Failed to set authentication tag")
    end
  end

  -- Decrypt the data
  decrypted_data = ctx:update(encrypted_data)
  decrypted_data = decrypted_data .. ctx:final()

  return decrypted_data
end

--[[
Description - get_random_hex_cmd:
- Generate a random hex string of the specified number of bytes.
If no length is specified, it will generate a hex string for 32 bytes (64 hex chars).

Parameters:
  - num_bytes: number?  - the number of bytes to generate a hex string from.
    If this is not specified, it will return a hex string of 64 characters.

Returns:
  - A string of hex characters.

Throws:
  - If num_bytes is not empty or a number, it will throw an error.

Example:
   - get_random_hex() - returns a hex string of 64 hex characters
   - get_random_hex(16) - returns a hex string of 32 hex characters
]]
---@param numberOfBytes number?
---@return string
function NASCrypto.get_random_hex_cmd(numberOfBytes)
  if numberOfBytes ~= nil and type(numberOfBytes) ~= "number" then
    error("numberOfBytes must be empty or must be a number")
  end

  numberOfBytes = numberOfBytes or 32

  local cmd = "openssl rand -hex " .. numberOfBytes

  return NASCrypto._exec_popen(cmd)
end

--[[
Description - get_random_hex:
- Generate a random hex string of the specified number of bytes.
If no length is specified, it will generate a hex string for 16 bytes (32 hex chars).

Parameters:
  - num_bytes: number?  - the number of bytes to generate a hex string from.
    If this is not specified, it will return a hex string of 16 bytes (32 hex chars).
  - uppercase: boolean? true for uppercase hex (A-F), false for lowercase (a-f)
    If this is not specified, it will default to lowercase (a-f).

Returns:
  - A string of hex characters.

Throws:
  - If luaossl rand.ready is false, it will throw an error.
  - If num_bytes is not empty or a number, it will throw an error.

Example:
   - get_random_hex() - returns a hex string of 32 hex characters
   - get_random_hex(16) - returns a hex string of 32 hex characters
   - get_random_hex(8, true) - returns a hex string of 16 uppercased hex characters
]]
-- Function to generate a random hex string of specified byte length.
---@param num_bytes number? Number of random bytes to generate (2 hex chars), default is 16
---@param uppercase boolean? true for uppercase hex (A-F), false for lowercase (a-f)
---@return string Random hex string of specified byte length
function NASCrypto.get_random_hex(num_bytes, uppercase)
  if not rand.ready() then
    error("Random number generator is not properly seeded")
  end

  if num_bytes ~= nil and type(num_bytes) ~= "number" then
    error("numberOfBytes must be empty or must be a number")
  end

  num_bytes = num_bytes or 16

  local bytes = rand.bytes(num_bytes)
  local hex = ""
  local format_str = uppercase and "%02X" or "%02x" -- Choose format based on uppercase param
  for i = 1, #bytes do
    hex = hex .. string.format(format_str, string.byte(bytes, i))
  end
  return hex
end

-- Generate a sequential GUID in the format unixtime_milliseconds-randhexbytes
---@param num_rand_bytes number? Number of random bytes to generate, default is 16
---@param uppercase boolean? true (default) for uppercase hex (A-F), false for lowercase
---@return string SGUID sequential GUID
function NASCrypto.get_sequential_guid(num_rand_bytes, uppercase)
  if uppercase == nil then uppercase = true end
  local unixtime_milliseconds = NASCrypto.unixtime_milliseconds()
  local rand_hex = NASCrypto.get_random_hex(num_rand_bytes, uppercase)

  return unixtime_milliseconds .. "-" .. rand_hex
end

--[[
Description - hash_password:
- Hash a password with a salt.
  Uses SHA512-based password algorithm

Parameters:
  - password: string - the password to hash.
    Password must not be empty and be 8 or more characters.
  - salt: string - the salt to use.

Returns:
  - hash: stringA hashed password.

Throws:
  - If the password is empty or not a string, it will throw an error.
  - If the salt is empty or not a string, it will throw an error.

Example:
    - hash_password("password", "salt") - returns a hashed password.
]]
---@param password string
---@param salt string
---@return string
function NASCrypto.hash_password(password, salt)
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
  local escaped_password = replace(password, '"', '\\"')
  local escaped_salt = replace(salt, '"', '\\"')
  local cmd = 'openssl passwd -6 -salt "'
      .. escaped_salt .. '" "'
      .. escaped_password .. '"'

  -- print("cmd", cmd)
  hash = NASCrypto._exec_popen(cmd)

  return hash
end

--[[
Description - hash_password_verify:
  - Verify a hashed password with the given salt.
    Uses SHA512-based password algorithm
  - Return true if the hashed password is correct, and false otherwise.

Parameters:
  - password: string - the password to verify.
    Password must not be empty and be 8 or more characters.
  - hashed_password: string - the hashed password to compare with.
  - salt: string - the salt to use.

Returns:
  - true if the hashed password is correct, and false otherwise.

Throws:
  - If the password is empty or less than 8 characters, it will throw an error.
  - If the hashed_password is empty or not a string, it will throw an error.
  - If the salt is empty or not a string, it will throw an error.

Example:
  - hash_password_verify("password", "$5$1234567890abcde", "salt")

]]
---@param password string
---@param hashed_password string
---@param salt string
---@return boolean
function NASCrypto.hash_password_verify(password, hashed_password, salt)
  if hashed_password == nil or type(hashed_password) ~= "string" then
    error("hashed_password must not be empty and must be a string")
  end

  local hash = NASCrypto.hash_password(password, salt)

  return hash == hashed_password
end

--[[
************************
*** END CRYPTO UTILS ***
************************
]]



--[[
************************
** BEGIN COMMON UTILS **
************************
]]

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
function NASCrypto._exec_popen(command, multi_line)
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
Description - unixtime_milliseconds:
  - Returns the current unix time in milliseconds.

]]
---@return integer
function NASCrypto.unixtime_milliseconds()
  --[[
    -- INTERNAL implementation.
    -- os.clock() does not have good accuracy
    local _, milliseconds = math.modf(os.clock() * 1000)
    return math.floor((milliseconds + os.time()) * 1000)
  ]]

  return math.floor(socket.gettime() * 1000)
end

--[[
************************
*** END COMMON UTILS ***
************************
]]

return NASCrypto
