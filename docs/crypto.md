# nas-utils.crypto

A Lua module providing cryptographic utilities for encoding, encryption, random generation, and password hashing.

## Table of Contents

- [bin2hex](#bin2hex)
- [hex2bin](#hex2bin)
- [base64encode](#base64encode)
- [base64decode](#base64decode)
- [hmac_hash](#hmac_hash)
- [encrypt](#encrypt)
- [decrypt](#decrypt)
- [get_random_hex_cmd](#get_random_hex_cmd)
- [get_random_hex](#get_random_hex)
- [get_sequential_guid](#get_sequential_guid)
- [hash_password](#hash_password)
- [hash_password_verify](#hash_password_verify)
- [unixtime_milliseconds](#unixtime_milliseconds)
- [Usage Example](#usage-example)

---

## bin2hex

**Convert a byte string to hexadecimal.**

```lua
NASCrypto.bin2hex(byte_string, uppercase)
```

- `byte_string` (`string`): Byte string to convert.
- `uppercase` (`boolean?`): Use uppercase hex (A-F) if true (default), lowercase (a-f) if false.
- **Returns:** `string` Hexadecimal representation.

---

## hex2bin

**Convert a hexadecimal string to a byte string.**

```lua
NASCrypto.hex2bin(hex_string)
```

- `hex_string` (`string`): Hexadecimal string (colons, dashes, spaces allowed).
- **Returns:** `string` Byte string.

---

## base64encode

**Base64 encode a string, with optional URL-safe encoding.**

```lua
NASCrypto.base64encode(data, url_safe)
```

- `data` (`string`): Data to encode.
- `url_safe` (`boolean?`): If true, makes encoding URL-safe (default: false).
- **Returns:** `string?` Base64 encoded string or nil if data is nil.

---

## base64decode

**Base64 decode a string, with optional URL-safe decoding.**

```lua
NASCrypto.base64decode(data, url_safe)
```

- `data` (`string`): Data to decode.
- `url_safe` (`boolean?`): If true, decodes URL-safe base64 (default: false).
- **Returns:** `string?` Decoded string or nil if data is nil.

---

## hmac_hash

**Produce an HMAC hash using a secret and digest algorithm.**

```lua
NASCrypto.hmac_hash(digest_algorithm, secret, data)
```

- `digest_algorithm` (`string`): Digest algorithm name (see `DigestType` enum, e.g. `"sha256"`).
- `secret` (`string`): Secret key for HMAC hashing.
- `data` (`string`): Data to hash.
- **Returns:** `string` Raw hashed bytes (not encoded).

---

## encrypt

**Encrypt data using a specified cipher.**

```lua
NASCrypto.encrypt(cipher_type, data, key, iv, tag_length)
```

- `cipher_type` (`Enum_CipherType`): Cipher type table.
- `data` (`string`): Data to encrypt.
- `key` (`string`): Encryption key.
- `iv` (`string?`): Initialization vector (optional).
- `tag_length` (`number?`): Tag length for GCM (default: 16).
- **Returns:** `{iv: string, encrypted_data: string, tag: string?}`

---

## decrypt

**Decrypt data using a specified cipher.**

```lua
NASCrypto.decrypt(cipher_type, encrypted_data, key, iv, tag)
```

- `cipher_type` (`Enum_CipherType`): Cipher type table.
- `encrypted_data` (`string`): Data to decrypt.
- `key` (`string`): Encryption key.
- `iv` (`string`): Initialization vector.
- `tag` (`string?`): Authentication tag for GCM (optional).
- **Returns:** `string?` Decrypted data or nil if decryption fails.

---

## get_random_hex_cmd

**Generate a random hex string using the `openssl` command.**

```lua
NASCrypto.get_random_hex_cmd(numberOfBytes)
```

- `numberOfBytes` (`number?`): Number of bytes (default: 32).
- **Returns:** `string` Hex string.

---

## get_random_hex

**Generate a random hex string using Lua.**

```lua
NASCrypto.get_random_hex(num_bytes, uppercase)
```

- `num_bytes` (`number?`): Number of bytes (default: 16).
- `uppercase` (`boolean?`): Uppercase hex (default: true).
- **Returns:** `string` Hex string.

---

## get_sequential_guid

**Generate a sequential GUID: `unixtime_milliseconds-randhexbytes`.**

```lua
NASCrypto.get_sequential_guid(num_rand_bytes, uppercase)
```

- `num_rand_bytes` (`number?`): Number of random bytes (default: 16).
- `uppercase` (`boolean?`): Uppercase hex (default: true).
- **Returns:** `string` Sequential GUID.

---

## hash_password

**Hash a password with a salt using SHA512-based algorithm.**

```lua
NASCrypto.hash_password(password, salt)
```

- `password` (`string`): Password (min 8 chars).
- `salt` (`string`): Salt string.
- **Returns:** `string` Hashed password.

---

## hash_password_verify

**Verify a password against a hashed password and salt.**

```lua
NASCrypto.hash_password_verify(password, hashed_password, salt)
```

- `password` (`string`): Password to verify.
- `hashed_password` (`string`): Hashed password.
- `salt` (`string`): Salt string.
- **Returns:** `boolean` True if password matches.

---

## unixtime_milliseconds

**Get the current Unix time in milliseconds.**

```lua
NASCrypto.unixtime_milliseconds()
```

- **Returns:** `integer` Unix time in milliseconds.

---

## Usage Example

```lua
local crypto = require("nas-utils.crypto")

local hex = crypto.bin2hex("abc") -- "616263"
local bytes = crypto.hex2bin("616263") -- "abc"
local b64 = crypto.base64encode("hello") -- "aGVsbG8="
local raw = crypto.base64decode("aGVsbG8=") -- "hello"
local hmac = crypto.hmac_hash("sha256", "secret", "data")
local randhex = crypto.get_random_hex(8) -- e.g. "A1B2C3D4E5F6A7B8"
local guid = crypto.get_sequential_guid() -- e.g. "1718040000000-ABCDEF1234567890"
local now = crypto.unixtime_milliseconds() -- e.g. 1718040000000

-- Password hashing
local hash = crypto.hash_password("mysecretpassword", "mysalt")
local ok = crypto.hash_password_verify("mysecretpassword", hash, "mysalt")
```

---

## License

MIT License

---

## Author

Michael Stephan, NetApplied Solutions

