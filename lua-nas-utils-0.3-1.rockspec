package = "lua-nas-utils"
version = "0.3-1"
source = {
   url = "git+ssh://git@github.com/NetApplied/lua-nas-utils.git"
}
description = {
   homepage = "*** please enter a project homepage ***",
   license = "*** please specify a license ***"
}
dependencies = {
   "lua ~> 5.1",
   "lua-cjson ~> 2.1",
   "inspect ~> 3.1",
   "luasec ~> 1.3",
   "luasocket ~> 3.1",
   "luaunit ~> 3.4"
}
build = {
   type = "builtin",
   modules = {
      init = "init.lua",
      ["nas-utils.crypto"] = "nas-utils/crypto.lua",
      ["nas-utils.helpers"] = "nas-utils/helpers.lua",
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
      ["nas-utils.rrule"] = "nas-utils/rrule.lua",
      ["nas-utils.strings"] = "nas-utils/strings.lua",
      ["tests.test_nas_utils_crypto"] = "tests/test_nas_utils_crypto.lua",
      ["tests.test_nas_utils_helpers"] = "tests/test_nas_utils_helpers.lua",
      ["tests.test_nas_utils_strings"] = "tests/test_nas_utils_strings.lua"
   },
   copy_directories = {
      "tests"
   }
}
