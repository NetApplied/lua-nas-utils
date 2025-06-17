-- nas-utils.logging.log_level.lua

local LogLevel      = {}

LogLevel._AUTHORS   = "Michael Stephan"
LogLevel._VERSION   = "0.3.1-1"
LogLevel._LICENSE   = "MIT License"
LogLevel._COPYRIGHT = "Copyright (c) 2025 NetApplied Solutions"

---@enum nas_utils.LogLevels
LogLevel.LogLevels  = {
    DEBUG = "DEBUG",
    INFO = "INFO",
    WARN = "WARN",
    ERROR = "ERROR",
    FATAL = "FATAL"
}

return LogLevel
