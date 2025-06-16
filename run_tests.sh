#!/bin/zsh
# cd to folder containing lua-nas-utils if running this outside of lua-nas-utils folder
eval "$(luarocks path --no-bin)"
./lua tests/test_nas_utils_helpers.lua -o tap
./lua tests/test_nas_utils_crypto.lua -o tap
./lua tests/test_nas_utils_strings.lua -o tap


