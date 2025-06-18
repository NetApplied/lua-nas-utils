# nas-utils

A collection of Lua utilities for NAS systems, providing helpers for cryptography, string manipulation, logging, and more.

## Table of Contents

- [Modules](#modules)
  - [helpers](#helpers)
  - [crypto](#crypto)
  - [strings](#strings)
  - [logger_rolling_file](#logger_rolling_file)
- [Enumerations](#enumerations)
  - [LogLevel](#loglevel)
  - [CipherType](#ciphertype)
  - [DigestType](#digesttype)
- [get_cipher_by_name](#get_cipher_by_name)
- [Usage Example](#usage-example)

---

## Modules

### helpers

General-purpose helper utilities for strings, tables, datetime, numbers, and system operations.

See: [helpers.md](./helpers.md)

### crypto

Cryptographic utilities for encoding, encryption, random generation, and password hashing.

See: [crypto.md](./crypto.md)

### strings

String manipulation utilities, similar to Python's string methods.

See: [strings.md](./strings.md)

### logger_rolling_file

Rolling file logger using the `logging.rolling_file` backend.

See: [logger_rolling_file.md](./logger_rolling_file.md)

---

## Enumerations

### LogLevel

Log level constants for use with logging.

| Name   | Value   | Description                                 |
|--------|---------|---------------------------------------------|
| DEBUG  | "DEBUG" | Fine-grained informational events           |
| INFO   | "INFO"  | General informational messages              |
| WARN   | "WARN"  | Potentially harmful situations              |
| ERROR  | "ERROR" | Error events                                |
| FATAL  | "FATAL" | Severe error events                         |

---

### CipherType

Cipher type tables for use with cryptographic functions.

Each cipher type is a table with these fields:

- `name` (`string`): Cipher name (e.g., `"aes-256-gcm"`)
- `key_length` (`number`): Key length in bytes
- `iv_length` (`number`): IV length in bytes
- `has_tag` (`boolean`): True if cipher uses authentication tag (GCM)

Example:

```lua
local CipherType = require("nas-utils").CipherType
local aes256gcm = CipherType.AES_256_GCM
print(aes256gcm.name) -- "aes-256-gcm"
```

---

### DigestType

Digest algorithm names for use with hashing.

| Name         | Value           |
|--------------|----------------|
| BLAKE2B512   | "blake2b512"   |
| BLAKE2S256   | "blake2s256"   |
| MD4          | "md4"          |
| MD5          | "md5"          |
| MDC2         | "mdc2"         |
| RMD160       | "rmd160"       |
| SHA1         | "sha1"         |
| SHA224       | "sha224"       |
| SHA256       | "sha256"       |
| SHA384       | "sha384"       |
| SHA512       | "sha512"       |
| SHA512_224   | "sha512-224"   |
| SHA512_256   | "sha512-256"   |
| SHA3_224     | "sha3-224"     |
| SHA3_256     | "sha3-256"     |
| SHA3_384     | "sha3-384"     |
| SHA3_512     | "sha3-512"     |
| SHAKE128     | "shake128"     |
| SHAKE256     | "shake256"     |
| SM3          | "sm3"          |

---

## get_cipher_by_name

**Retrieve a cipher type table by name.**

```lua
local cipher_type = require("nas-utils").get_cipher_by_name(cipher_name)
```

- `cipher_name` (`string`): Name of the cipher (case-insensitive).
- **Returns:** `CipherType` table or `nil` if not found.

---

## Usage Example

```lua
local nas = require("nas-utils")

-- Use helpers
print(nas.helpers.trim("  hello  ")) -- "hello"

-- Use crypto
local guid = nas.crypto.get_sequential_guid()

-- Use strings
print(nas.strings.capitalize("hello world")) -- "Hello world"

-- Use logger
local logger = nas.logger_rolling_file.get_log({filename = "myapp.log"})
logger:info("Started app")

-- Use enumerations
local aes256gcm = nas.CipherType.AES_256_GCM
print(aes256gcm.name) -- "aes-256-gcm"

local level = nas.LogLevel.DEBUG
print(level) -- "DEBUG"
```

---

## License

MIT License

---

## Author

Michael Stephan, NetApplied Solutions
