/*
 * Lua 5.x C API type definitions for radare2
 *
 * Covers Lua 5.1 / 5.2 / 5.3 / 5.4 (compatible subset).
 * Common in: OpenWrt router firmware, embedded scripting, game engines,
 * network appliances (Cisco, Juniper), DJI drone apps.
 *
 * Usage:
 *   to lua/lua.h
 *   tf lua_pcall           # show pcall signature
 *   tsc lua_Debug          # show debug info struct
 *   te lua_type_tag        # show type constants
 *
 * Note: lua_State is always an opaque pointer in disassembly -- recognise it
 * as the first argument to virtually every Lua C API function.
 */

/* ============================================================================
 * Type tags (LUA_TNONE through LUA_TTHREAD)
 * Returned by lua_type()
 * ============================================================================ */

enum lua_type_tag {
    LUA_TNONE          = -1,
    LUA_TNIL           = 0,
    LUA_TBOOLEAN       = 1,
    LUA_TLIGHTUSERDATA = 2,
    LUA_TNUMBER        = 3,
    LUA_TSTRING        = 4,
    LUA_TTABLE         = 5,
    LUA_TFUNCTION      = 6,
    LUA_TUSERDATA      = 7,
    LUA_TTHREAD        = 8
};

/* ============================================================================
 * Comparison operators for lua_compare() (Lua 5.2+)
 * ============================================================================ */

enum lua_cmp_op {
    LUA_OPEQ = 0,   /* == */
    LUA_OPLT = 1,   /* < */
    LUA_OPLE = 2    /* <= */
};

/* ============================================================================
 * Arithmetic operators for lua_arith() (Lua 5.2+)
 * ============================================================================ */

enum lua_arith_op {
    LUA_OPADD  = 0,
    LUA_OPSUB  = 1,
    LUA_OPMUL  = 2,
    LUA_OPMOD  = 3,
    LUA_OPPOW  = 4,
    LUA_OPDIV  = 5,
    LUA_OPIDIV = 6,  /* Lua 5.3+ integer division */
    LUA_OPBAND = 7,  /* Lua 5.3+ bitwise AND */
    LUA_OPBOR  = 8,
    LUA_OPBXOR = 9,
    LUA_OPSHL  = 10,
    LUA_OPSHR  = 11,
    LUA_OPUNM  = 12,
    LUA_OPBNOT = 13
};

/* ============================================================================
 * Thread / coroutine status
 * ============================================================================ */

enum lua_status {
    LUA_OK        = 0,
    LUA_YIELD     = 1,
    LUA_ERRRUN    = 2,
    LUA_ERRSYNTAX = 3,
    LUA_ERRMEM    = 4,
    LUA_ERRGCMM   = 5,  /* Lua 5.2 GC metamethod error */
    LUA_ERRERR    = 6
};

/* ============================================================================
 * GC opcodes for lua_gc()
 * ============================================================================ */

enum lua_gc_op {
    LUA_GCSTOP       = 0,
    LUA_GCRESTART    = 1,
    LUA_GCCOLLECT    = 2,
    LUA_GCCOUNT      = 3,
    LUA_GCCOUNTB     = 4,
    LUA_GCSTEP       = 5,
    LUA_GCSETPAUSE   = 6,
    LUA_GCSETSTEPMUL = 7,
    LUA_GCISRUNNING  = 9   /* Lua 5.2+ */
};

/* ============================================================================
 * Hook events (lua_sethook / lua_Debug.event)
 * ============================================================================ */

enum lua_hook_event {
    LUA_HOOKCALL    = 0,
    LUA_HOOKRET     = 1,
    LUA_HOOKLINE    = 2,
    LUA_HOOKCOUNT   = 3,
    LUA_HOOKTAILCALL = 4
};

/* Hook masks for lua_sethook() */
enum lua_hook_mask {
    LUA_MASKCALL  = 1,   /* 1 << LUA_HOOKCALL */
    LUA_MASKRET   = 2,   /* 1 << LUA_HOOKRET */
    LUA_MASKLINE  = 4,   /* 1 << LUA_HOOKLINE */
    LUA_MASKCOUNT = 8    /* 1 << LUA_HOOKCOUNT */
};

/* ============================================================================
 * Pseudo-indices for registry and upvalues
 * (Values depend on LUAI_MAXSTACK, typical for 32-bit builds)
 * ============================================================================ */

enum lua_pseudo_index {
    LUA_REGISTRYINDEX = -10000,
    LUA_ENVIRONINDEX  = -10001,  /* Lua 5.1 only */
    LUA_GLOBALSINDEX  = -10002   /* Lua 5.1 only */
};

/* ============================================================================
 * Debug structure (lua_Debug) -- used by lua_getstack / lua_getinfo
 * ============================================================================ */

struct lua_Debug {
    int event;
    char *name;             /* function name (or NULL) */
    char *namewhat;         /* "global", "local", "method", etc. */
    char *what;             /* "Lua", "C", "main", "tail" */
    char *source;           /* source file/chunk name */
    int currentline;        /* current line in source */
    int linedefined;        /* line where function was defined */
    int lastlinedefined;    /* last line of function definition */
    char nups;              /* number of upvalues */
    char nparams;           /* number of fixed parameters (Lua 5.2+) */
    char isvararg;          /* is function vararg? */
    char istailcall;        /* was called via tail call? (Lua 5.2+) */
    char short_src[60];     /* short source name for error messages */
    /* private fields follow */
};

/* ============================================================================
 * luaL_Reg -- function table entry for luaL_newlib / luaL_register
 * ============================================================================ */

struct luaL_Reg {
    char *name;      /* function name in the Lua table */
    void *func;      /* C function pointer: int (*)(lua_State*) */
};

/* ============================================================================
 * luaL_Buffer -- string buffer for luaL_Buffer operations
 * ============================================================================ */

struct luaL_Buffer {
    char *b;         /* current position in buffer */
    int size;        /* buffer size */
    void *L;         /* associated lua_State */
    /* internal fields follow */
};

/* ============================================================================
 * Core API function signatures
 *
 * All functions take lua_State* (void*) as first argument.
 * Stack positions: 1 = bottom, -1 = top (most recently pushed).
 * ============================================================================ */

/* State management */
void *luaL_newstate(void);
void *lua_newstate(void *alloc_fn, void *ud);
void lua_close(void *L);
void *lua_newthread(void *L);

/* Library loading */
void luaL_openlibs(void *L);
int luaopen_base(void *L);
int luaopen_table(void *L);
int luaopen_io(void *L);
int luaopen_os(void *L);
int luaopen_string(void *L);
int luaopen_math(void *L);
int luaopen_debug(void *L);
int luaopen_package(void *L);

/* Stack manipulation */
int lua_gettop(void *L);
void lua_settop(void *L, int idx);
void lua_pushvalue(void *L, int idx);
void lua_remove(void *L, int idx);
void lua_insert(void *L, int idx);
void lua_replace(void *L, int idx);
int lua_checkstack(void *L, int extra);
void lua_xmove(void *from, void *to, int n);

/* Type checking */
int lua_type(void *L, int idx);
char *lua_typename(void *L, int tp);
int lua_isnumber(void *L, int idx);
int lua_isstring(void *L, int idx);
int lua_iscfunction(void *L, int idx);
int lua_isinteger(void *L, int idx);  /* Lua 5.3+ */
int lua_isuserdata(void *L, int idx);
int lua_isthread(void *L, int idx);

/* Value reading */
long long lua_tointeger(void *L, int idx);
long long lua_tointegerx(void *L, int idx, void *isnum);  /* Lua 5.2+ */
double lua_tonumber(void *L, int idx);
double lua_tonumberx(void *L, int idx, void *isnum);
int lua_toboolean(void *L, int idx);
char *lua_tolstring(void *L, int idx, void *len);
char *lua_tostring(void *L, int idx);  /* macro wrapping tolstring */
int lua_rawlen(void *L, int idx);
void *lua_tocfunction(void *L, int idx);
void *lua_touserdata(void *L, int idx);
void *lua_tothread(void *L, int idx);
void *lua_topointer(void *L, int idx);

/* Pushing values */
void lua_pushnil(void *L);
void lua_pushnumber(void *L, double n);
void lua_pushinteger(void *L, long long n);
void lua_pushlstring(void *L, char *s, int len);
void lua_pushstring(void *L, char *s);
void lua_pushvfstring(void *L, char *fmt, void *argp);
void lua_pushfstring(void *L, char *fmt);
void lua_pushcclosure(void *L, void *fn, int n);
void lua_pushboolean(void *L, int b);
void lua_pushlightuserdata(void *L, void *p);
int lua_pushthread(void *L);

/* Table access */
int lua_getglobal(void *L, char *name);
void lua_setglobal(void *L, char *name);
int lua_gettable(void *L, int idx);
int lua_getfield(void *L, int idx, char *k);
int lua_geti(void *L, int idx, long long n);       /* Lua 5.3+ */
int lua_rawget(void *L, int idx);
int lua_rawgeti(void *L, int idx, long long n);
int lua_rawgetp(void *L, int idx, void *p);
void lua_createtable(void *L, int narr, int nrec);
void *lua_newuserdata(void *L, int size);
void *lua_newuserdatauv(void *L, int size, int nuvalue);  /* Lua 5.4 */
int lua_getmetatable(void *L, int objindex);
int lua_getuservalue(void *L, int idx);
void lua_settable(void *L, int idx);
void lua_setfield(void *L, int idx, char *k);
void lua_seti(void *L, int idx, long long n);       /* Lua 5.3+ */
void lua_rawset(void *L, int idx);
void lua_rawseti(void *L, int idx, long long n);
void lua_rawsetp(void *L, int idx, void *p);
int lua_setmetatable(void *L, int objindex);
void lua_setuservalue(void *L, int idx);

/* Function calls */
void lua_call(void *L, int nargs, int nresults);
void lua_callk(void *L, int nargs, int nresults, long long ctx, void *k);
int lua_pcall(void *L, int nargs, int nresults, int msgh);
int lua_pcallk(void *L, int nargs, int nresults, int msgh, long long ctx, void *k);
int lua_load(void *L, void *reader, void *dt, char *chunkname, char *mode);
int lua_dump(void *L, void *writer, void *data, int strip);

/* Coroutines */
int lua_resume(void *L, void *from, int nargs);
int lua_status(void *L);
int lua_isyieldable(void *L);
int lua_yield(void *L, int nresults);
int lua_yieldk(void *L, int nresults, long long ctx, void *k);

/* GC */
int lua_gc(void *L, int what, int data);

/* Error handling */
int lua_error(void *L);
int lua_next(void *L, int idx);
void lua_concat(void *L, int n);
void lua_len(void *L, int idx);

/* Debug */
int lua_getstack(void *L, int level, struct lua_Debug *ar);
int lua_getinfo(void *L, char *what, struct lua_Debug *ar);
char *lua_getlocal(void *L, struct lua_Debug *ar, int n);
char *lua_setlocal(void *L, struct lua_Debug *ar, int n);
char *lua_getupvalue(void *L, int funcindex, int n);
char *lua_setupvalue(void *L, int funcindex, int n);
int lua_sethook(void *L, void *func, int mask, int count);
void *lua_gethook(void *L);
int lua_gethookmask(void *L);
int lua_gethookcount(void *L);

/* ============================================================================
 * Auxiliary library (luaL_*) -- higher-level helpers
 * ============================================================================ */

void luaL_checkversion(void *L);
int luaL_getmetafield(void *L, int obj, char *e);
int luaL_callmeta(void *L, int obj, char *e);
char *luaL_tolstring(void *L, int idx, void *len);
int luaL_argerror(void *L, int arg, char *extramsg);
char *luaL_checklstring(void *L, int arg, void *l);
char *luaL_optlstring(void *L, int arg, char *def, void *l);
double luaL_checknumber(void *L, int arg);
double luaL_optnumber(void *L, int arg, double def);
long long luaL_checkinteger(void *L, int arg);
long long luaL_optinteger(void *L, int arg, long long def);
void luaL_checkstack(void *L, int sz, char *msg);
void luaL_checktype(void *L, int arg, int t);
void luaL_checkany(void *L, int arg);
int luaL_newmetatable(void *L, char *tname);
void luaL_setmetatable(void *L, char *tname);
void *luaL_testudata(void *L, int ud, char *tname);
void *luaL_checkudata(void *L, int ud, char *tname);
void luaL_where(void *L, int lvl);
int luaL_error(void *L, char *fmt);
int luaL_checkoption(void *L, int arg, char *def, void *lst);
int luaL_fileresult(void *L, int stat, char *fname);
int luaL_execresult(void *L, int stat);
int luaL_ref(void *L, int t);
void luaL_unref(void *L, int t, int ref);
int luaL_loadfilex(void *L, char *filename, char *mode);
int luaL_loadfile(void *L, char *filename);
int luaL_loadbufferx(void *L, char *buff, int sz, char *name, char *mode);
int luaL_loadbuffer(void *L, char *buff, int sz, char *name);
int luaL_loadstring(void *L, char *s);
int luaL_dofile(void *L, char *filename);
int luaL_dostring(void *L, char *str);
void luaL_newlibtable(void *L, void *l);
void luaL_newlib(void *L, void *l);
void luaL_register(void *L, char *libname, struct luaL_Reg *l);
int luaL_getsubtable(void *L, int idx, char *fname);
void luaL_traceback(void *L, void *L1, char *msg, int level);
void luaL_requiref(void *L, char *modname, void *openf, int glb);
void luaL_buffinit(void *L, struct luaL_Buffer *B);
char *luaL_prepbuffsize(struct luaL_Buffer *B, int sz);
void luaL_addlstring(struct luaL_Buffer *B, char *s, int l);
void luaL_addstring(struct luaL_Buffer *B, char *s);
void luaL_addvalue(struct luaL_Buffer *B);
void luaL_pushresult(struct luaL_Buffer *B);
void luaL_pushresultsize(struct luaL_Buffer *B, int sz);
char *luaL_buffinitsize(void *L, struct luaL_Buffer *B, int sz);
