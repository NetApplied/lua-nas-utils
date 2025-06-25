package = "lua-nas-utils"
version = "0.3.2-1"
source = {
   url = "git+https://github.com/NetApplied/lua-nas-utils",
   tag = "v0.3.2",
}
description = {
   homepage = "https://github.com/NetApplied/lua-nas-utils",
   license = "MIT",
   summary = "Lua utility modules for working with cryptography, datetime, strings, etc.",
   detailed = [[
      A collection of Lua utility modules for NAS systems, providing helpers for 
      cryptography, datetime, string manipulation, logging, JWT, and more.
   ]]
}
dependencies = {
   "lua >= 5.1",
   "lua-cjson ~> 2.1",
   "inspect ~> 3.1",
   "luasocket ~> 3.1",
   "luaunit ~> 3.4",
   "luaossl ~> 20220711"
}
build = {
   type = "builtin",
   modules = {
      ["nas-utils.crypto"] = "nas-utils/crypto.lua",
      ["nas-utils.helpers"] = "nas-utils/helpers.lua",
      ["nas-utils.init"] = "nas-utils/init.lua",
      ["nas-utils.jwt"] = "nas-utils/jwt.lua",
      ["nas-utils.logger_rolling_file"] = "nas-utils/logger_rolling_file.lua",
      ["nas-utils.logging.console"] = "nas-utils/logging/console.lua",
      ["nas-utils.logging.email"] = "nas-utils/logging/email.lua",
      ["nas-utils.logging.envconfig"] = "nas-utils/logging/envconfig.lua",
      ["nas-utils.logging.file"] = "nas-utils/logging/file.lua",
      ["nas-utils.logging.logging"] = "nas-utils/logging/logging.lua",
      ["nas-utils.logging.nginx"] = "nas-utils/logging/nginx.lua",
      ["nas-utils.logging.rolling_file"] = "nas-utils/logging/rolling_file.lua",
      ["nas-utils.logging.rsyslog"] = "nas-utils/logging/rsyslog.lua",
      ["nas-utils.logging.socket"] = "nas-utils/logging/socket.lua",
      ["nas-utils.logging.sql"] = "nas-utils/logging/sql.lua",
      ["nas-utils.strings"] = "nas-utils/strings.lua"
   }
}
