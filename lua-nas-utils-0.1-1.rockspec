package = "lua-nas-utils"
version = "0.1-1"
source = {
   url = "git+ssh://git@github.com/NetApplied/lua-nas-utils.git"
}
description = {
   summary = "Lua helper utilities",
   homepage = "*** please enter a project homepage ***",
   license = "MIT"
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
   modules = {}
}
