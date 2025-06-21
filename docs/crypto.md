# nas-utils.crypto

A Lua module providing cryptographic utilities for encoding, encryption, random generation, and password hashing.

## Table of Contents

- [bin2hex](#bin2hex)
- [hex2bin](#hex2bin)
- [base64encode](#base64encode)
- [base64decode](#base64decode)
- [hmac_hash](#hmac_hash)
- [kdf_derive](#kdf_derive)
- [encrypt](#encrypt)
- [decrypt](#decrypt)
- [get_random_bytes](#get_random_bytes)
- [get_random_hex](#get_random_hex)
- [get_sequential_guid](#get_sequential_guid)
- [hash_password](#hash_password)
- [hash_password_verify](#hash_password_verify)
- [unixtime_milliseconds](#unixtime_milliseconds)
- [Usage Example](#usage-example)
- [See Also](#see-also)

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
- **Returns:** `string` Base64 encoded string.

---

## base64decode

**Base64 decode a string, with optional URL-safe decoding.**

```lua
NASCrypto.base64decode(data, url_safe)
```

- `data` (`string`): Data to decode.
- `url_safe` (`boolean?`): If true, decodes URL-safe base64 (default: false).
- **Returns:** `string` Decoded string.

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

## kdf_derive

**Key derivation using PBKDF2, HKDF, etc.**

```lua
NASCrypto.kdf_derive(kdf_options, output_hex)
```

- `kdf_options` (`table`): Options for key derivation (see luaossl docs; e.g. type, md, outlen, pass, salt, iter).
- `output_hex` (`boolean?`): Output as hex string (default: false).
- **Returns:** `string` Derived key (bytes or hex).

---

## encrypt

**Encrypt data using a specified cipher.**

```lua
local status, result = NASCrypto.encrypt(cipher_type, data, key, iv, tag_length)
```

- `cipher_type` (`Enum_CipherType`): Cipher type table.
- `data` (`string`): Data to encrypt.
- `key` (`string`): Encryption key.
- `iv` (`string?`): Initialization vector (optional).
- `tag_length` (`number?`): Tag length for GCM (default: 16).
- **Returns:**
  - `status` (`boolean`): true if success, false if error
  - `result` (`table|string`): `{iv, encrypted_data, tag}` table if success, or error message if failure

---

## decrypt

**Decrypt data using a specified cipher.**

```lua
local status, result = NASCrypto.decrypt(cipher_type, encrypted_data, key, iv, tag)
```

- `cipher_type` (`Enum_CipherType`): Cipher type table.
- `encrypted_data` (`string`): Data to decrypt.
- `key` (`string`): Encryption key.
- `iv` (`string`): Initialization vector.
- `tag` (`string?`): Authentication tag for GCM (optional).
- **Returns:**
  - `status` (`boolean`): true if success, false if error
  - `result` (`string`): Decrypted data if success, or error message if failure

---

## get_random_bytes

**Generate cryptographically secure random bytes.**

```lua
NASCrypto.get_random_bytes(num_bytes)
```

- `num_bytes` (`number?`): Number of bytes (default: 16).
- **Returns:** `string` Random bytes.

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

**Hash a password with a salt using PBKDF2-HMAC-SHA512, PBKDF2-HMAC-SHA256, Argon2i, or Argon2id.**

Note: Argon2i and Argon2id are only supported on systems with OpenSSL 3.2 or higher.

```lua
NASCrypto.hash_password(password, salt, iterations, algorithm)
```

- `password` (`string`): Password (min 8 chars).
- `salt` (`string?`): Salt string (optional; random if not provided).
- `iterations` (`number?`): Number of iterations (default: 250000 for pbkdf2_sha512, 300000 for pbkdf2_sha256, 10 for argon2i/argon2id).
- `algorithm` (`string?`): Hashing algorithm (default: "pbkdf2_sha512"). **Supported values:** `"pbkdf2_sha512"`, `"pbkdf2_sha256"`, `"argon2i"`, `"argon2id"`.
- **Returns:** `string` Hash format: `algorithm$iterations$b64_salt$b64_pw_hash`.

---

## hash_password_verify

**Verify a password against a hash format string.**

```lua
NASCrypto.hash_password_verify(password, hash_format)
```

- `password` (`string`): Password to verify (min 8 chars).
- `hash_format` (`string`): Hash format string: `algorithm$iterations$b64_salt$b64_pw_hash`.
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
local hash = crypto.hash_password("mysecretpassword")
local ok = crypto.hash_password_verify("mysecretpassword", hash)
```

---

## See Also
- [nas-utils (overview)](./nas-utils.md)
- [jwt](./jwt.md)
- [strings](./strings.md)
- [helpers](./helpers.md)
- [logger_rolling_file](./logger_rolling_file.md)

---

## License

MIT License.  
Copyright (c) 2025 Net Applied Solutions, LLC.  
All rights reserved.
    
See [LICENSE](./LICENSE) for details.


