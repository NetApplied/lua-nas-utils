package = "lua-nas-utils"
version = "0.3.1-1"
source = {
   url = "git+https://github.com/NetApplied/lua-nas-utils"
}
description = {
   homepage = "https://github.com/NetApplied/lua-nas-utils",
   license = "MIT",
   summary = "Lua utility for working with cryptography, dates and time, strings, etc."
}
dependencies = {
   "lua ~> 5.1",
   "lua-cjson ~> 2.1",
   "inspect ~> 3.1",
   "luasocket ~> 3.1",
   "luaunit ~> 3.4"
}
build = {
   type = "builtin",
   modules = {
      ["nas-utils.crypto"] = "nas-utils/crypto.lua",
      ["nas-utils.helpers"] = "nas-utils/helpers.lua",
      ["nas-utils.init"] = "nas-utils/init.lua",
      ["nas-utils.logger_rolling_file"] = "nas-utils/logger_rolling_file.lua",
      ["nas-utils.logging.console"] = "nas-utils/logging/console.lua",
      ["nas-utils.logging.email"] = "nas-utils/logging/email.lua",
      ["nas-utils.logging.envconfig"] = "nas-utils/logging/envconfig.lua",
      ["nas-utils.logging.file"] = "nas-utils/logging/file.lua",
      ["nas-utils.logging.log_level"] = "nas-utils/logging/log_level.lua",
      ["nas-utils.logging.logging"] = "nas-utils/logging/logging.lua",
      ["nas-utils.logging.nginx"] = "nas-utils/logging/nginx.lua",
      ["nas-utils.logging.rolling_file"] = "nas-utils/logging/rolling_file.lua",
      ["nas-utils.logging.rsyslog"] = "nas-utils/logging/rsyslog.lua",
      ["nas-utils.logging.socket"] = "nas-utils/logging/socket.lua",
      ["nas-utils.logging.sql"] = "nas-utils/logging/sql.lua",
      ["nas-utils.strings"] = "nas-utils/strings.lua"
   }
}
