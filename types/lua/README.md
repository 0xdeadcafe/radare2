# types/lua/ — Lua 5.x C API type definitions

Type definitions for the Lua 5.x C API (compatible subset covering 5.1–5.4).

## Why This Matters

Lua is embedded in:
- **OpenWrt** router firmware (UCI, LuCI web UI calls into Lua)
- **Cisco IOS-XE / NX-OS** scripting engine
- **Juniper Junos** op scripts, commit scripts
- **Game engines** (Valve, CryEngine, LÖVE)
- **DJI mobile apps** (scripting layer)
- **NGINX** (OpenResty/ngx_lua)
- Any binary calling `luaL_newstate` / `lua_pcall`

## Usage

```r2
to lua/lua.h
tf lua_pcall            # protected call signature
tf luaL_loadstring      # load and compile a string as Lua code
tsc lua_Debug           # debug info struct
te lua_type_tag         # value type constants
te lua_status           # call/resume return codes
```

## Quick Analysis Workflow

```r2
aa
# Find Lua entry points
afl~lua
# Find where Lua state is created (root of the call tree)
axt sym.imp.luaL_newstate
# Find all C→Lua call sites
axt sym.imp.lua_pcall
axt sym.imp.lua_call
# Find registered C functions
/c luaL_register
/c luaL_newlib
```

## Detecting Lua Version

| Function | Lua version |
|----------|-------------|
| `lua_tointegerx` present | 5.2+ |
| `lua_isinteger` present | 5.3+ |
| `lua_newuserdatauv` present | 5.4+ |
| `lua_geti` / `lua_seti` present | 5.3+ |
| `LUA_ENVIRONINDEX` used | 5.1 |

## Notes

- `lua_State*` (void*) is always the first argument
- Stack index 1 = bottom of current frame, -1 = top (most recently pushed)
- `luaL_error` never returns (calls longjmp internally)
- `lua_pcall` returns `LUA_OK` (0) on success; error message left on stack on failure
