package = "lua-nas-utils"
version = "0.1-2"
source = {
   url = "git+ssh://git@github.com/NetApplied/lua-nas-utils.git"
}
description = {
   homepage = "*** please enter a project homepage ***",
   license = "*** please specify a license ***"
}
build = {
   type = "builtin",
   modules = {
      init = "init.lua",
      ["utils.NASCrypto"] = "utils/NASCrypto.lua",
      ["utils.NASHelpers"] = "utils/NASHelpers.lua",
      ["utils.NASPyString"] = "utils/NASPyString.lua",
      ["utils.logging.console"] = "utils/logging/console.lua",
      ["utils.logging.email"] = "utils/logging/email.lua",
      ["utils.logging.envconfig"] = "utils/logging/envconfig.lua",
      ["utils.logging.file"] = "utils/logging/file.lua",
      ["utils.logging.logging"] = "utils/logging/logging.lua",
      ["utils.logging.nginx"] = "utils/logging/nginx.lua",
      ["utils.logging.rolling_file"] = "utils/logging/rolling_file.lua",
      ["utils.logging.rsyslog"] = "utils/logging/rsyslog.lua",
      ["utils.logging.socket"] = "utils/logging/socket.lua",
      ["utils.logging.sql"] = "utils/logging/sql.lua",
      ["utils.rrule"] = "utils/rrule.lua",
      ["utils.tests.test_utils_nas_crypto"] = "utils/tests/test_utils_nas_crypto.lua",
      ["utils.tests.test_utils_nas_helpers"] = "utils/tests/test_utils_nas_helpers.lua",
      ["utils.tests.test_utils_nas_pystring"] = "utils/tests/test_utils_nas_pystring.lua"
   }
}
