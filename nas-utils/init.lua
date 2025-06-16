-- init.lua

-- return all listed modules in modules.path

local modules = {}
modules._Authors = "Michael Stephan"
modules._Version = "0.3-1"
modules._License = "MIT License"
modules._Homepage = "https://github.com/NetApplied/lua-nas-utils"
modules._Description = "A collection of Lua utilities for NAS systems."

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

return modules
