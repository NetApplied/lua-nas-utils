-- nas-utils.crypto.lua

local NASCrypto      = {}

NASCrypto._AUTHORS   = "Michael Stephan"
NASCrypto._VERSION   = "0.3.2-1"
NASCrypto._LICENSE   = "MIT License"
NASCrypto._COPYRIGHT = "Copyright (c) 2025 NetApplied Solutions"

local socket         = require("socket")         -- luasocket
local rand           = require("openssl.rand")   -- luaossl
local cipher         = require("openssl.cipher") -- luaossl
local hmac           = require("openssl.hmac")   -- luaossl
local kdf            = require("openssl.kdf")    -- luaossl
local b64encode      = require("mime").b64       -- luasocket
local b64decode      = require("mime").unb64     -- luasocket


--[[
********************
*** CRYPTO UTILS ***
********************
]]


-- Convert a byte string to hexadecimal
---@param byte_string string Byte string to convert.
---@param uppercase boolean? default true for uppercase hex (A-F), false for lowercase (a-f)
---@return string hex_string Hexadecimal representation of the byte string.
function NASCrypto.bin2hex(byte_string, uppercase)
  if uppercase == nil then uppercase = true end

  local hex = ""
  local strformat = uppercase and "%02X" or "%02x" -- Choose format based on uppercase param
  for i = 1, #byte_string do
    hex = hex .. string.format(strformat, string.byte(byte_string, i))
  end

  return hex
end

-- Convert a hexadecimal string to byte string.
-- Strips any colons, dashes, or spaces from the string.
---@param hex_string string Hexadecimal string to convert into byte string.
---@return string byte_string Byte representation of the hexadecimal string.
function NASCrypto.hex2bin(hex_string)
  -- Remove colons, dashes, and spaces from the hex string
  hex_string = hex_string:gsub("[ %-:]", "")

  local byteString = ""
  for i = 1, #hex_string, 2 do
    local byte = tonumber(hex_string:sub(i, i + 1), 16)
    byteString = byteString .. string.char(byte)
  end
  return byteString
end

-- Base64 encoding with url safe option
---@param data string Data to encode
---@param url_safe boolean? Option to make the encoding URL-safe (default is false)
---@return string encoded The base64 encoded string or nil if data is nil
function NASCrypto.base64encode(data, url_safe)
  url_safe = url_safe or false
  if not data then error("data string must be provided") end

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
---@return string decoded The base64 decoded string or nil if data is nil
function NASCrypto.base64decode(data, url_safe)
  url_safe = url_safe or false
  if not data then error("data string must be provided") end

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

---@alias Crypto_KdfOptions {type: string, outlen: number, pass: string, salt: string,
---iter: number, md: Enum_DigestType?, key: string?, maxmem_bytes: number?, secret: string?}

-- Key derivation function. 
--
-- Will throw an error if type is unsupported or kdf_options are wrong
--
-- Complete kdf_options: {type: string, outlen: number, pass: string, salt: string,
-- iter: number, md: Enum_DigestType?, key: string?, maxmem_bytes: number?, secret: string?,
-- seed: string?, hkdf_mode: string?, info: string?, N: number?, r: number?, p: number?}
--
-- If you are using the output for password hashing, then the output length:
-- - Must be no more than the native hash's output size:
--    - SHA-1 is 20 bytes,
--    - SHA-224 is 28 bytes,
--    - SHA-256 is 32 bytes,
--    - SHA-384 is 48 bytes,
--    - SHA-512 is 64 bytes
-- - Must be no less than your risk tolerance. In practice, anything less than 20 bytes
-- (SHA-1 native output size) is too small.
--
-- If you are using the output directly as only a single encryption key:
--
-- - Should be equal to the size of the encryption key you need.
-- Ideally is also no more than the native hash's output size (see above)
---@param kdf_options Crypto_KdfOptions Table of options for kdf derivation
---@param output_hex boolean? Default is false (byte string output)
---@return string derived_key Byte string or hex representation of bytes
function NASCrypto.kdf_derive(kdf_options, output_hex)
  output_hex = output_hex and true or false

  local derived_key = kdf.derive(kdf_options)

  -- check if hex output requested
  derived_key = output_hex and NASCrypto.bin2hex(derived_key) or derived_key

  return derived_key
end

-- Produce a hmac hash using a secret
---@param digest_algorithm Enum_DigestType Digest algorithm to be used for hmac hashing
---@param secret string Secret for hmac hashing
---@param data string Data to hash
---@return string digest Hashed bytes without encoding
function NASCrypto.hmac_hash(digest_algorithm, secret, data)
  local ctx = hmac.new(secret, digest_algorithm)
  ctx:update(data)
  local digest = ctx:final()

  return digest
end

---@alias Crypto_EncryptedDataTable {iv: string, encrypted_data: string, tag: string? }
-- Encrypts data using the specified cipher. If cipher uses GCM mode, a tag is generated.
--
-- Returns status code and data
---@param cipher_type Enum_CipherType `Enum_CipherType` to use for encryption.
---@param data string Data to be encrypted
---@param key string Encryption key of appropriate length
---@param iv string? Initialization vector of appropriate length. Generated if not provided
---@param tag_length number? Length of the authentication tag. Max and default is 16 bytes
---@return boolean status Returns false if error
---@return Crypto_EncryptedDataTable|string encrypted_data_table Table of byte strings or error message
function NASCrypto.encrypt(cipher_type, data, key, iv, tag_length)
  tag_length = tag_length or 16 -- Default to 16 bytes if not specified

  if cipher_type == nil or data == nil or key == nil then
    return false, "Must provide cipher, data and key"
  end

  if type(cipher_type) ~= "table" then
    return false, "cipher_enum parameter must be Enum_CipherType table"
  end

  -- Ensure the key and IV are of appropriate length for the chosen cipher
  local key_length = cipher_type.key_length
  local iv_length = cipher_type.iv_length

  -- if iv not provided, generate a random one
  if iv == nil then
    if not rand.ready() then
      return false, "Random number generator is not properly seeded"
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
    return false, "Failed to create cipher context for " .. cipher_type.name
  end

  -- Initialize the cipher for encryption
  if not ctx:encrypt(key, iv) then
    return false, "Failed to initialize cipher for encryption"
  end

  -- Encrypt the data
  local encrypted_data = ctx:update(data)
  encrypted_data = encrypted_data .. ctx:final()

  -- get authentication tag if supported by cipher
  local tag = cipher_type.has_tag and ctx:getTag(tag_length) or nil

  return true, {
    iv = iv,
    encrypted_data = encrypted_data,
    tag = tag
  }
end

-- Decrypts data using the specified cipher. If cipher uses GCM, a tag must be provided.
--
-- Returns status code and data
---@param cipher_type Enum_CipherType `Enum_CipherType` to use for encryption.
---@param encrypted_data string Data to be decrypted
---@param key string Encryption key of appropriate length
---@param iv string Initialization vector of appropriate length.
---@param tag string? Optional authentication tag required if cipher uses GCM.
---@return boolean status Returns false if error
---@return string data data or error message if decryption fails.
function NASCrypto.decrypt(cipher_type, encrypted_data, key, iv, tag)
  local decrypted_data = nil

  if cipher_type == nil or encrypted_data == nil or key == nil or iv == nil then
    return false, "Must provide cipher, encrypted_data, key and iv"
  end

  if type(cipher_type) ~= "table" then
    return false, "cipher_enum parameter must be Enum_CipherType table"
  end

  if cipher_type.has_tag and tag == nil then
    return false, "Tag is required for " .. (cipher_type.name or "GCM") .. " mode"
  end

  -- Ensure the key and IV are of appropriate length for the chosen cipher
  local key_length = cipher_type.key_length
  local iv_length = cipher_type.iv_length

  if #iv < iv_length then
    return false, "IV for " .. cipher_type.name .. " must be at least "
        .. iv_length .. " bytes"
  end

  if #key < key_length then
    return false, "Key for " .. cipher_type.name .. " must be at least "
        .. key_length .. " bytes"
  end

  key = string.sub(key, 1, key_length)
  iv = string.sub(iv, 1, iv_length)

  -- Create a new cipher context
  local ctx = cipher.new(cipher_type.name)
  if not ctx then
    return false, "Failed to create cipher context for " .. cipher_type.name
  end

  -- Initialize the cipher for decryption
  if not ctx:decrypt(key, iv) then
    return false, "Failed to initialize cipher for decryption"
  end

  if cipher_type.has_tag then
    if not ctx:setTag(tag) then
      return false, "Failed to set authentication tag"
    end
  end

  -- Decrypt the data
  decrypted_data = ctx:update(encrypted_data)
  decrypted_data = decrypted_data .. ctx:final()

  return true, decrypted_data
end

-- Generates cryptographically secure random bytes
--
-- Throws an error if num_bytes is not a number or luaossl rand.ready is false
---@param num_bytes number? Integer number of bytes to generate, default is 16
---@return string byte_string Randomized byte string
function NASCrypto.get_random_bytes(num_bytes)
  if num_bytes ~= nil and type(num_bytes) ~= "number" then
    error("num_bytes must be empty or must be a number")
  end

  -- make sure number is integer
  num_bytes = num_bytes and math.floor(num_bytes) or 16

  if not rand.ready() then
    error("random number generator is not properly seeded")
  end

  return rand.bytes(num_bytes)
end

--[[
Description - get_random_hex:
- Generate a random hex string of the specified number of bytes.
If no length is specified, it will generate a hex string for 16 bytes (32 hex chars).

Parameters:
  - num_bytes: number?  - the number of bytes to generate a hex string from.
    If this is not specified, it will return a hex string of 16 bytes (32 hex chars).
  - uppercase: boolean? true for uppercase hex (A-F), false for lowercase (a-f)
    If this is not specified, it will default to uppercase (A-F).

Returns:
  - A string of hex characters.

Throws:
  - If luaossl rand.ready is false, it will throw an error.
  - If num_bytes is not empty or a number, it will throw an error.

Example:
   - get_random_hex() - returns a hex string of 32 hex characters
   - get_random_hex(16) - returns a hex string of 32 hex characters
   - get_random_hex(8, false) - returns a hex string of 16 lowercased hex characters
]]
-- Function to generate a random hex string of specified byte length.
---@param num_bytes number? Number of random bytes to generate (2 hex chars), default is 16
---@param uppercase boolean? default true for uppercase hex (A-F), false for lowercase (a-f)
---@return string Random hex string of specified byte length
function NASCrypto.get_random_hex(num_bytes, uppercase)
  if uppercase == nil then uppercase = true end

  num_bytes = num_bytes or 16

  local bytes = NASCrypto.get_random_bytes(num_bytes)

  return NASCrypto.bin2hex(bytes, uppercase)
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
- PBKDF2 key derivation method, using HMAC-SHA512 pseudorandom function by default

Parameters:
  - password: string - the password to hash.
    Password must not be empty and be 8 or more characters.
  - salt: string - Optional salt to use.  If not provided, a random salt will be generated.
  - iterations: number - Optional number of iterations to use for hashing.
    Default is 250,000 iterations, but can be set to a higher value for more security.
  - algorithm: string - Optional password hashing algorithm to use.
    Default and only supported algorithm is "pbkdf2_sha512".

Returns:
  - hash_format: string - format *"algorithm$iterations$b64_salt$b64_pw_hash"*.

Throws:
  - If the password is empty or not a string, it will throw an error.
  - If the salt is empty or not a string, it will throw an error.

Example:
    - hash_password("password", "salt") - returns a hashed password.
]]
-- Pasword hashing using PBKDF2_HMAC-SHA512 pseudorandom function by default
---@param password string Password to hash. Must be 8 or more characters.
---@param salt string? Salt to use for hashing, or nil to generate a random salt.
---@param iterations number? Optional number of iterations, default is 250,000 iterations.
---@param algorithm string? Optional hashing algorithm, default pbkdf2_sha512
---@return string hash_format format of "algorithm$iterations$b64_salt$b64_pw_hash"
function NASCrypto.hash_password(password, salt, iterations, algorithm)
  if password == nil or type(password) ~= "string" or #password < 8 then
    error("password must not be empty and must be 8 or more characters")
  end

  if salt ~= nil and type(salt) ~= "string" then
    error("salt must be empty or must be a string")
  end

  if iterations ~= nil and type(iterations) ~= "number" then
    error("iterations must be empty or must be a number")
  end

  local kdf_options = {}
  iterations = iterations or 250000 -- Default to 250,000 iterations
  salt = salt or NASCrypto.get_random_bytes(24)
  algorithm = algorithm or "pbkdf2_sha512"

  -- check for supported algorithms
  if algorithm == "pbkdf2_sha512" then
    kdf_options.type = "pbkdf2"
    kdf_options.md = "sha512"
    kdf_options.outlen = 64 -- SHA512 native output size is 64 bytes
  else
    error("Unsupported algorithm: " .. algorithm)
  end

  kdf_options.pass = password
  kdf_options.salt = salt
  kdf_options.iter = iterations

  local pass_hash_bytes = NASCrypto.kdf_derive(kdf_options)

  local str_format = "%s$%d$%s$%s"
  local b64salt = NASCrypto.base64encode(salt, true)
  local b64hash = NASCrypto.base64encode(pass_hash_bytes, true)

  return string.format(str_format, algorithm, iterations, b64salt, b64hash)
end


--[[
Description - hash_password_verify:
  - Verify a password against the provided hash_format string
    "algorithm$iterations$b64_salt$b64_pw_hash".

  - Return true if the hashed password is correct, and false otherwise.

Parameters:
  - password: string - the password to verify.
    Password must not be empty and be 8 or more characters.
  - hash_format: string - "algorithm$iterations$b64_salt$b64_pw_hash" to compare with.

Returns:
  - true if the hashed password matches given password, and false otherwise.

Throws an error:
  - If the password is empty or less than 8 characters
  - If the hashed_format string is empty or not correct format

Example:
  - hash_password_verify("password", "pbkdf2_sha512$250000$b64_salt$b64_pw_hash")

]]
-- Verifies a password against the hash format string
-- "algorithm$iterations$b64_salt$b64_pw_hash"
---@param password string Password must not be empty and be 8 or more characters
---@param hash_format string Format: "algorithm$iterations$b64_salt$b64_pw_hash"
---@return boolean verified Returns true if password matches hash, false otherwise
function NASCrypto.hash_password_verify(password, hash_format)
  if password == nil or type(password) ~= "string" or #password < 8 then
    error("password must not be empty and must be 8 or more characters")
  end

  if hash_format == nil or type(hash_format) ~= "string" then
    error("hash_format must not be empty and must be a string")
  end

  local parts = { hash_format:match('([^$]+)$(%d+)$([^$]+)$([^$]+)') }
  if #parts ~= 4 then
    error("Invalid hash format, expected 'algorithm$iterations$b64_salt$b64_pw_hash'")
  end

  local algorithm, iterations, b64_salt, _ = unpack(parts)
  iterations = tonumber(iterations) or 1 -- tonumber can return nil

  local salt = NASCrypto.base64decode(b64_salt, true)

  return hash_format == NASCrypto.hash_password(password, salt, iterations, algorithm)

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
