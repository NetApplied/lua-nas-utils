# nas-utils.logger_rolling_file

A Lua module providing a rolling file logger using the `logging.rolling_file` backend.

## Table of Contents

- [get_log](#get_log)
- [Log Levels](#log-levels)
- [Usage Example](#usage-example)

---

## get_log

**Get a rolling file logger instance.**

```lua
LoggerRollingFile.get_log(config_table)
```

- `config_table` (`table?`): Optional configuration table:
  - `filename` (`string?`): Log file name (default: `"app.log"`).
  - `maxFileSize` (`number?`): Maximum file size in bytes (default: `1048576`).
  - `maxBackupIndex` (`number?`): Number of backup files (default: `5`).
  - `timestampPattern` (`string?`): Timestamp format (default: `"!%Y-%m-%dT%H:%M:%S.%qZ"`).
  - `logLevel` (`string?`): Log level (default: `"INFO"`).

**Returns:** logger instance.

---

## Log Levels

- `DEBUG`: Fine-grained informational events.
- `INFO`: General informational messages.
- `WARN`: Potentially harmful situations.
- `ERROR`: Error events.
- `FATAL`: Severe error events.
- `OFF`: Disables all logging.

---

## Usage Example

```lua
local logger = require("nas-utils.logger_rolling_file").get_log({
  filename = "myapp.log",
  maxFileSize = 1024 * 1024,
  maxBackupIndex = 3,
  logLevel = "DEBUG"
})

logger:info("Application started")
logger:error("An error occurred")
```

---

## License

MIT License.  
Copyright (c) 2025 Net Applied Solutions, LLC.  
All rights reserved.
    
See [LICENSE](./LICENSE) for details.

