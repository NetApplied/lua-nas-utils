# lua-nas-utils

A collection of Lua utility modules for NAS systems, providing helpers for cryptography, string manipulation, logging, and more.

## Features

- **Cryptography**: Hex, base64, password hashing, encryption/decryption, random generation.
- **String Utilities**: Python-style string methods, splitting, joining, case conversion, and more.
- **Helpers**: Table, datetime, number, and system utilities.
- **Logging**: Rolling file logger with configurable log levels and rotation.

## Modules

- [`crypto`](./docs/crypto.md): Cryptographic utilities.
- [`strings`](./docs/strings.md): String manipulation functions.
- [`helpers`](./docs/helpers.md): General-purpose helpers.
- [`logger_rolling_file`](./docs/logger_rolling_file.md): Rolling file logger.

See the [full documentation in the `docs` folder](./docs/) for detailed API reference and usage examples.

## Installation

Install via [LuaRocks](https://luarocks.org/modules/netapplied/lua-nas-utils):

```sh
luarocks install lua-nas-utils
```

This will automatically install all required dependencies.

## Basic Usage

```lua
local nas = require("nas-utils")

-- String utilities
print(nas.strings.capitalize("hello world")) -- "Hello world"

-- Cryptography
local guid = nas.crypto.get_sequential_guid()

-- Logging
local logger = nas.logger_rolling_file.get_log({filename = "myapp.log"})
logger:info("Started app")
```

## Documentation

- [nas-utils (overview)](./docs/nas-utils.md)
- [crypto](./docs/crypto.md)
- [strings](./docs/strings.md)
- [helpers](./docs/helpers.md)
- [logger_rolling_file](./docs/logger_rolling_file.md)


## License

MIT License.  
Copyright (c) 2025 NetApplied Solutions
    
See [LICENSE](./LICENSE) for details.
