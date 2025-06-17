-- nas-utils.init.lua

local modules               = {}

modules._AUTHORS            = "Michael Stephan"
modules._VERSION            = "0.3.1-1"
modules._LICENSE            = "MIT License"
modules._COPYRIGHT          = "Copyright (c) 2025 NetApplied Solutions"
modules._HOMEPAGE           = "https://github.com/NetApplied/lua-nas-utils"
modules._DESCRIPTION        = "A collection of Lua utilities for NAS systems."

modules.helpers             = require("nas-utils.helpers")
modules.crypto              = require("nas-utils.crypto")
modules.strings             = require("nas-utils.strings")
modules.logger_rolling_file = require("nas-utils.logger_rolling_file")
modules.LogLevels           = require("nas-utils.logging.log_level").LogLevels

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
