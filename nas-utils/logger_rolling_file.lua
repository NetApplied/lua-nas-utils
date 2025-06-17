-- nas-utils.logger_rolling_file.lua

local LoggerRollingFile      = {}

LoggerRollingFile._AUTHORS   = "Michael Stephan"
LoggerRollingFile._VERSION   = "0.3.2-1"
LoggerRollingFile._LICENSE   = "MIT License"
LoggerRollingFile._COPYRIGHT = "Copyright (c) 2025 NetApplied Solutions"


---@diagnostic disable-next-line: undefined-doc-name
---@alias nas-utils.logging.rolling_file logging.rolling_file
require "nas-utils.logging.rolling_file"


-- Get rolling file logger instance
--
-- Default values for config_table:
-- - filename: "app.log"
-- - maxFileSize: (1024 * 1024) 1MB
-- - maxBackupIndex: 5
-- - timestampPattern: "!%Y-%m-%dT%H:%M:%S.%qZ"
-- - logLevel: "INFO"
--
--  @param: config_table - table with configuration values for the logger, or default values
---@param config_table {filename: string?, maxFileSize: number?, maxBackupIndex: number?,
---timestampPattern: string?, logLevel: string?}?
---@return nas-utils.logging.rolling_file logger instance
function LoggerRollingFile.get_log(config_table)
    config_table = config_table or {}

    -- set defaults
    config_table.filename = config_table.filename or "app.log"
    config_table.maxFileSize = config_table.maxFileSize or (1024 * 1024) -- 1MB
    config_table.maxBackupIndex = config_table.maxBackupIndex or 5
    config_table.timestampPattern = config_table.timestampPattern or "!%Y-%m-%dT%H:%M:%S.%qZ"
    config_table.logLevel = config_table.logLevel or "INFO"

    return logging.rolling_file(config_table)
end

return LoggerRollingFile



--[[

usage:
local log = require("nas-utils").logger_rolling_file({filename = "app.log"})
log:debug("This is a debug message")
log:info("This is an info message")
log:warn("This is a warning message")
log:error("This is an error message")
log:fatal("This is a fatal message")


Constants - logLevel:
logger.DEBUG
The DEBUG level designates fine-grained informational events that are most useful to debug
an application.

logger.INFO
The INFO level designates informational messages that highlight the progress of the
application at coarse-grained level.

logger.WARN
The WARN level designates potentially harmful situations.

logger.ERROR
The ERROR level designates error events that might still allow the application to continue
running.

logger.FATAL
The FATAL level designates very severe error events that would presumably lead the
application to abort.

logger.OFF
The OFF level will stop all log messages.

]]
