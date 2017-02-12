#!/usr/bin/env tarantool

local ffi = require('ffi')
local fio = require('fio')
local fun = require('fun')
local log = require('log')
local json = require('json')
local errno = require('errno')
local argparse = require('internal.argparse').parse

local yaml  = require('yaml').new()
yaml.cfg{
    encode_invalid_numbers = true,
    encode_load_metatable = true,
    encode_use_tostring = true,
    encode_invalid_as_nil = true,
}

ffi.cdef[[
    typedef int uid_t;
    typedef int gid_t;
    typedef int time_t;

    uid_t getuid(void);

    struct group {
        char    *gr_name;    /* group name */
        char    *gr_passwd;  /* group password */
        gid_t    gr_gid;     /* group id */
        char   **gr_mem;     /* group members */
    };

    struct group *getgrgid(gid_t gid);
]]

if ffi.os == 'OSX' or ffi.os == 'BSD' then
    ffi.cdef[[
        struct passwd {
            char    *pw_name;    /* user name */
            char    *pw_passwd;  /* encrypted password */
            uid_t    pw_uid;     /* user uid */
            gid_t    pw_gid;     /* user gid */
            time_t   pw_change;  /* password change time */
            char    *pw_class;   /* user access class */
            char    *pw_gecos;   /* Honeywell login info */
            char    *pw_dir;     /* home directory */
            char    *pw_shell;   /* default shell */
            time_t   pw_expire;  /* account expiration */
            int      pw_fields;  /* internal: fields filled in */
        };
    ]]
else
    ffi.cdef[[
        struct passwd {
            char *pw_name;   /* username */
            char *pw_passwd; /* user password */
            int   pw_uid;    /* user ID */
            int   pw_gid;    /* group ID */
            char *pw_gecos;  /* user information */
            char *pw_dir;    /* home directory */
            char *pw_shell;  /* shell program */
        };
    ]]
end

ffi.cdef[[
    struct passwd *getpwuid(uid_t uid);
    struct passwd *getpwnam(const char *login);
]]

-- logger
--   || API:
--   || write, debug, error (3 levels, for now)
--   ==
--
-- tarantoolctl
--   || Plugin API:
--   || * register_library
--   || * register_alias
--   || * register_config
--   || Public API:
--   || !! absent
--   \/
-- library
--   || Plugin API:
--   || * register_method
--   || * register_prepare
--   || Public API:
--   || !! absent
--   \/
-- method
--   || Plugin API:
--   || !! absent
--   || Public API:
--   || * config_get
--   ==

local DEFAULT_DEFAULTS_PATH = '/etc/default/tarantool'
local DEFAULT_PLUGIN_PATH   = '/etc/tarantool/plugins'
local DEFAULT_WRAPPER_NAME  = 'cli'

local tarantoolctl

--------------------------------------------------------------------------------
--                            logging abstraction                             --
--------------------------------------------------------------------------------

-- io.stdout:setvbuf('line')
io.stderr:setvbuf('line')

local default_stream = setmetatable({
    stream = io.stderr
}, {
    __index = {
        write = function(self, prefix, string)
            if prefix == 'error | ' then
                prefix = ''
            end
            self.stream:write(prefix, string, '\n')
        end,
        flush = function(self)
            self.stream:flush()
        end
    }
})

local tntlog_stream = setmetatable({
}, {
    __index = {
        write = function(self, prefix, string)
            if prefix then
                if prefix:match("debug") then
                    return log.debug(string)
                elseif prefix:match("error") then
                    return log.error(string)
                end
            end
            log.info(string)
        end,
        flush = function() end
    }
})

local function logger_closure(verbosity, prefix)
    return function(self, fmt, ...)
        if self.verbosity < verbosity then
            return
        end
        assert(type(fmt) == 'string')
        local stat = true
        if select('#', ...) > 0 then
            stat, fmt = pcall(string.format, fmt, ...)
        end
        if not stat then
            error(fmt, 2)
        end
        self.stream:write(prefix, fmt)
    end
end

local function logger_new(verbosity)
    local logger = setmetatable({
        stream    = default_stream,
        verbosity = verbosity
    }, {
        __index = {
            write = logger_closure(0, ''),
            debug = logger_closure(1, 'debug | '),
            error = logger_closure(0, 'error | '),
            syserror = function(self, fmt, ...)
                if select('#', ...) > 0 then
                    fmt = fmt:format(...)
                end
                self.stream:write(
                    'error | ',
                    string.format(
                        '[errno %d] %s: %s',
                        errno(), fmt, errno.strerror()
                    )
                )
            end,
            get_traceback = function(self, ldepth)
                local tb = {}
                local level = 2 + (ldepth or 1)
                while true do
                    local info = debug.getinfo(level)
                    assert(type(info) == 'nil' or type(info) == 'table')
                    if info == nil then
                        break
                    end
                    table.insert(tb, {
                        line = info.currentline or 0,
                        what = info.what or 'undef',
                        file = info.short_src or info.src or 'eval',
                        name = info.name,
                    })
                    level = level + 1
                end
                return tb
            end,
            write_traceback = function(self, level, ldepth)
                level = level and self[level] or self.debug
                for _, frame in ipairs(self:get_traceback(ldepth)) do
                    local name = ''
                    if frame.name ~= nil then
                        name = (" function '%s'"):format(frame.name)
                    end
                    level(self, "[%-4s]%s at <%s:%d>", frame.what, name,
                                 frame.file, frame.line)
                end
            end,
            -- :error_xc([level,] format, ...)
            error_xc = function(self, ...)
                local fmt_pos, level = 2, 2
                local fmt = ...
                if type(fmt) == 'number' then
                    fmt_pos = 3
                    level, fmt = ...
                end
                -- format error message
                local stat = true
                if select('#', ...) >= fmt_pos then
                    stat, fmt = pcall(
                        string.format, select(fmt_pos - 1, ...)
                    )
                end
                error(fmt, stat == false and 2 or level)
            end,
            -- :syserror_xc([level,] format, ...)
            syserror_xc = function(self, ...)
                local fmt_pos, level = 2, 2
                local fmt = ...
                if type(fmt) == 'number' then
                    fmt_pos = 3
                    level, fmt = ...
                end
                -- format error message
                fmt = '[errno %d] ' .. fmt .. ': ' .. errno.strerror()
                local stat, fmt = pcall(
                    string.format, fmt, errno(), select(fmt_pos, ...)
                )
                error(fmt, stat == false and 2 or level)
            end,
            stream_set_tarantool = function(self)
                self.stream = tntlog_stream
            end
        }
    })
    package.loaded['ctl.log'] = logger
    return logger
end

local logger = logger_new(1)

--------------------------------------------------------------------------------
--                                 Utilities                                  --
--------------------------------------------------------------------------------

local user_cache = setmetatable({}, {
    __index = function(self, uid)
        local group_info, user_info, rv, gid = nil, nil, {}, -1
        do
            if type(uid) == 'number' then
                errno(0); user_info = ffi.C.getpwuid(uid)
                if user_info == nil then
                    if errno() == 0 then
                        logger:debug("can't find user with uid '%d'", uid)
                    else
                        logger:error("getpwuid failed [errno %d]: %s", errno(),
                                     errno.strerror())
                    end
                    return nil
                end
            elseif type(uid) == 'string' then
                errno(0); user_info = ffi.C.getpwnam(uid)
                if user_info == nil then
                    if errno() == 0 then
                        logger:debug("can't find user with username '%d'", uid)
                    else
                        logger:error("getpwnam failed [errno %d]: %s", errno(),
                                     errno.strerror())
                    end
                    return nil
                end
            else
                assert(false)
            end
            rv = {
                name = ffi.string(user_info.pw_name),
                uid  =    tonumber(user_info.pw_uid),
                home =    tonumber(user_info.pw_dir)
            }
        end
        do
            local gid = user_info.pw_gid
            errno(0); group_info = ffi.C.getgrgid(gid)
            if group_info ~= nil then
                rv.group = {
                    name = ffi.string(group_info.gr_name),
                    gid  =   tonumber(group_info.gr_gid)
                }
            else
                if errno() == 0 then
                    logger:debug("can't find group with gid '%d'", gid)
                else
                    logger:error("getgrgid failed [errno %d]: %s",
                                errno(), errno.strerror())
                end
            end
        end
        rawset(self, rv.uid, rv)
        rawset(self, rv.name, rv)
        return rv
    end
})

local function user_get(user)
    if user == nil then
        user = tonumber(ffi.C.getuid())
    end
    return user_cache[user]
end

local function chain_maps(...)
    local rval = {}
    for _, val in ipairs({...}) do
        for k, v in pairs(val) do
            rval[k] = v
        end
    end
    return rval
end

local function is_main()
    return debug.getinfo(2).what == "main" and pcall(debug.getlocal, 5, 1) == false
end

local function execute_wrapped(func, ...)
    local function xpcall_traceback_callback(err)
        if err == 'usage' then
            return err
        end
        err = err or '<none>'
        if type(err) == 'cdata' then
            err = tostring(err)
        end
        local err_place = nil
        if err:match(':%d+: ') then
            err_place, err = err:match('(.+:%d+): (.+)')
        end
        logger:error('Error catched: %s', err)
        if err_place ~= nil then
            logger:error("Error occured at '%s'", err_place)
        end
        logger:error('')
        logger:write_traceback('error', 2)
        return err
    end

    return xpcall(func, xpcall_traceback_callback, ...)
end

local function is_callable(arg)
    if arg ~= nil then
        local mt = (type(arg) == 'table' and getmetatable(arg) or nil)
        if type(arg) == 'function' or mt ~= nil and type(mt.__call) == 'function' then
            return true
        end
    end
    return false
end

local function string_split(path, separator)
   local fields, separator = {}, separator or '.'
   path:gsub("([^" .. separator .. "]+)", function(c) table.insert(fields, c) end)
   return #fields, fields
end

local function split_config(path)
    local fields = {}
    path:gsub("([^.]+)", function(c) table.insert(fields, c) end)
    return #fields, fields
end

local function load_sandboxed(path, env, desc)
    local path = fio.abspath(path)
    local ufunc, msg = loadfile(path)
    if not ufunc then
        logger:error("Failed to load %s file '%s':", desc, path)
        logger:error(msg)
        return false
    end
    debug.setfenv(ufunc, setmetatable(env, { __index = _G }))
    local rval = { pcall(ufunc) }
    if not rval[1] then
        logger:error("Failed to execute %s file '%s':", desc, path)
        logger:error(rval[2])
        return false
    end
    return unpack(rval)
end

package.loaded['ctl.utils'] = {
    user_get        = user_get,
    string_split    = string_split,
    execute_wrapped = execute_wrapped,
}
--------------------------------------------------------------------------------
--                               Configuration                                --
--------------------------------------------------------------------------------

local function tarantoolctl_cfg_new()
    local cfg = {
        values = {},
        defaults = {},
        formats = setmetatable({
            lua = function(self, default_path)
                local function load_dictionary(self, name, value)
                    -- assume, that dicts have only string keys (for now)
                    name = name == nil and '' or name .. '.'
                    for subname, subvalue in pairs(value) do
                        subname = name .. subname
                        if type(subvalue) == 'table' then
                            load_dictionary(self, subname, subvalue)
                        else
                            self.values[subname] = subvalue
                        end
                    end
                end

                local result_environment = {}
                load_sandboxed(default_path, result_environment, 'defaults')
                load_dictionary(self, nil, result_environment)
            end
        }, {
            __index = function(self, format)
                self:error('unknown config format "%s"', format)
            end
        })
    }
    return setmetatable(cfg, {
        __index = {
            register = function(self, name, tp, default)
                assert(type(default) ~= 'nil')
                self.defaults[name] = {tp, default}
            end,
            get = function(self, name)
                if self.values[name] == nil then
                    local default = self.defaults[name][2]
                    if is_callable(default) then
                        default = default()
                    end
                    self.values[name] = default
                end
                local tp = self.defaults[name][1]
                if type(self.values[name]) ~= tp then
                    logger:error('config "%s": expected type "%s", got "%s"',
                                        name, tp, type(self.values[name]))
                    return nil
                end
                return self.values[name]
            end,
            load = function(self, default_path)
                if default_path == nil then
                    return
                end
                local ext_len, ext = split_config(fio.basename(default_path))
                local format = ext_len > 1 and ext[ext_len] or 'lua'
                self.formats[format](self, default_path)
            end,
        },
    })
end

--------------------------------------------------------------------------------
--                        library/methods abstractions                        --
--------------------------------------------------------------------------------

local constructors = {
    library = nil,
    method = nil,
}

local function register_alias(self, name, dotted_path, cfg)
    logger:debug("registering alias '%s' to '%s'", name, dotted_path)
    local n, path = split_config(dotted_path)
    local lname, mname = unpack(path)
    if n ~= 2 then
        logger:error("bad alias path '%s' (expected 2 components, got %d)",
                     dotted_path, n)
        return nil
    end
    local library = self.libraries[lname]
    if library == nil then
        logger:error("bad alias path '%s' (library '%s' not found)",
                     dotted_path, lname)
        return nil
    end
    local method = library.methods[mname]
    if method == nil then
        logger:error("bad alias path '%s' (method '%s' not found)",
                     dotted_path, lname)
        return nil
    end

    cfg = cfg or {}

    self.aliases[name] = {
        path = dotted_path,
        deprecated = cfg.deprecated or false
    }

    return method:plugin_api()
end

local function register_config(self, name, tp, default)
    logger:debug("registering configuration value '%s'", name)
    logger:debug("type '%s'. defaults to '%s'", tp, default)
    self.cfg:register(name, tp, default)
end

local function register_prepare(self, callback)
    logger:debug("registering context prepare function '%s'",
                 tostring(callback))
    table.insert(self.prepare, callback)
end

local function register_library(self, name, opts)
    logger:debug("registering library '%s'", name, opts)
    if self.libraries[name] ~= nil then
        logger:error("failted to register library. already exists")
        return nil
    end
    assert(self.libraries[name] == nil)

    local lib_instance = constructors.library(name, opts)
    self.libraries[name] = lib_instance

    return lib_instance:plugin_api()
end

local function register_method(self, name, callback, opts)
    logger:debug("registering method '%s'", name)
    assert(self.methods[name] == nil)

    local meth_instance = constructors.method(name, callback, opts)
    self.methods[name] = meth_instance

    return meth_instance:plugin_api()
end

local function get_config(self, name)
    logger:debug("getting configuration value for '%s'", name)
    return self.cfg:get(name)
end

local function usage_header()
    logger:error("Tarantool client utility (%s)", _TARANTOOL)
    logger:error("Usage:")
    logger:error("")
end

-- split long line into muple one's with max width of 80 charachters and
-- prepends with depth spaces
local function prepare_description(lines, depth)
    local fields = {}
    if lines ~= nil then
        lines:gsub("([^\n]+)", function(val)
            local rv = val:gsub("^%s*(.-)%s*$", "%1")
            local fs = string.byte(rv, 1)
            if fs ~= 44 and fs ~= 46 and fs ~= 58 and fs ~= 59 then
                rv = ' ' .. rv
            end
            table.insert(fields, rv)
        end)
    end
    lines = table.concat(fields, '')
    fields = {}
    while true do
        if #lines == 0 then break end
        local line = nil
        if #lines <= 80 then
            line = lines
        else
            line = lines:sub(0, 80 - depth + 1):match("(.*%s)[^%s]*")
        end
        if not line or #line == 0 then
            line = lines:sub(0, 80 - depth) .. '-'
        end
        lines = lines:sub(#line + 1)
        line = line:gsub("^%s*(.-)%s*$", "%1")
        table.insert(fields, string.rep(' ', depth) .. line)
    end
    return fields
end

constructors.method = function(name, cb, description)
    -- checks must be here
    return setmetatable({
        name         = name,
        callback     = cb,
        description  = description or {},
    }, {
        __index = {
            run = function(self, ctx)
                logger:debug("calling callback '%s'", self.name)
                local rv = execute_wrapped(self.callback, ctx)
                if rv == 'usage' then
                    return self:usage()
                end
                if self.exiting or rv == false then
                    os.exit(rv and 0 or 1)
                end
                return rv
            end,
            usage = function(self, opts)
                opts = opts or {}
                opts.depth = opts.depth

                local header = self.description.header
                if tarantoolctl.linkmode then
                    if not self.description.linkmode then
                        return
                    end
                    header = self.description.linkmode
                end
                if type(header) ~= 'table' then header = { header } end
                for _, line in ipairs(header) do
                    line = line:format(tarantoolctl.program_name)
                    local is_first_line = false
                    for _, line in ipairs(
                        prepare_description(line, opts.depth)
                    ) do
                        if is_first_line then line = '    ' .. line end
                        logger:write(line)
                        is_first_line = true
                    end
                end

                opts.detailed = opts.detailed or tarantoolctl.help
                if opts.detailed then
                    local description = self.description.description
                    logger:write("")
                    for _, line in ipairs(
                        prepare_description(description, opts.depth + 2)
                    ) do
                        logger:write(line)
                    end
                    local arguments   = self.description.arguments
                    logger:write("")
                    if arguments then
                        for _, arg in ipairs(arguments) do
                            logger:write('%s%s',
                                         string.rep(' ', opts.depth + 2),
                                         arg[1])
                            for _, line in ipairs(
                                prepare_description(arg[2], opts.depth + 4)
                            ) do
                                logger:write(line)
                            end
                        end
                        logger:write("")
                    end
                end
                return false
            end,
            plugin_api = function(self)
                return self
            end,
            public_api = function(self)
                return self
            end
        },
    })
end

constructors.library = function(name, description)
    return setmetatable({
        name        = name,
        command     = nil,
        methods     = {},
        prepare     = {},
        ctx         = {},
        description = description or {},
        arguments   = tarantoolctl.arguments,
    }, {
        __index = {
            plugin_api = function(self)
                return setmetatable(fun.iter(self):tomap(), {
                    __index = {
                        register_method = register_method,
                        register_prepare = register_prepare
                    },
                })
            end,
            public_api = function(self)
                return self
            end,
            return_sorted = function(self)
                local sorted = fun.iter(self.methods):map(function(name, val)
                    return {val.description.weight or 0, name}
                end):totable();
                table.sort(sorted, function(l, r) return l[1] < r[1] end)
                return fun.iter(sorted):map(function(value)
                    return self.methods[value[2]]
                end):totable()
            end,
            usage = function(self, opts)
                opts = opts or {}
                opts.depth    = opts.depth    or 0
                opts.detailed = opts.detailed or tarantoolctl.help
                local nested = opts.nested

                if tarantoolctl.linkmode then
                    local have_linkmode = false
                    for name, method in pairs(self.methods) do
                        if method.description.linkmode then
                            have_linkmode = true
                            break
                        end
                    end
                    if not have_linkmode then
                        if not opts.nested then
                            logger:error("%s library doesn't support link mode",
                                        self.name)
                        end
                        return
                    end
                end

                if self.command == nil then
                    if nested then
                        logger:write("%s[%s library]",
                                     string.rep(' ', opts.depth),
                                     self.name, self.description.weight)
                    else
                        logger:error("Expected command name, got nothing")
                    end
                elseif self.methods[self.command] == nil then
                    logger:error("Command '%s' isn't found in module '%s'",
                                 self.command, name)
                end
                if not nested then
                    logger:error("")
                    usage_header()
                end
                opts.depth = opts.depth + 4
                for _, val in ipairs(self:return_sorted()) do
                    val:usage(opts)
                    opts.first = true
                end
                opts.depth = opts.depth - 4
                -- TODO: write usage function
                return false
            end,
            run = function(self)
                self.command = table.remove(self.arguments, 1)
                if self.command == nil then
                    return self:usage()
                end
                local wrapper = self.methods[self.command]
                if wrapper == nil or tarantoolctl.help then
                    return self:usage()
                end
                do -- prepare context here
                    self.ctx.command_name = self.command
                    self.ctx.positional_arguments = {}
                    self.ctx.keyword_arguments    = {}
                    for k, v in pairs(tarantoolctl.arguments) do
                        if type(k) == 'number' then
                            self.ctx.positional_arguments[k] = v
                        else
                            self.ctx.keyword_arguments[k] = v
                        end
                    end
                    for _, cb in ipairs(self.prepare) do
                        logger:debug("running context prepare function '%s'", tostring(cb))
                        if cb(tarantoolctl:public_api(), self.ctx) == false then
                            return self:usage()
                        end
                    end
                end
                return wrapper:run(self.ctx)
            end,
        },
    })
end

tarantoolctl = setmetatable({
    libraries = {},
    aliases   = {},
    plugins   = {},
    cfg = tarantoolctl_cfg_new(),
}, {
    __index = {
        load_defaults = function(self, defaults_path)
            self.cfg:load(defaults_path)
        end,
        load_plugins = function(self, plugin_dir_path)
            local function plugin_count_len(plugin_no, plugin_count)
                local cnt = #tostring(plugin_count)
                return string.format('%0'.. cnt .. 'd/%0' .. cnt .. 'd',
                                    plugin_no, plugin_count)
            end

            logger:debug("loading plugins from '%s'", plugin_dir_path)
            if fio.stat(plugin_dir_path) == nil then
                logger:debug("failed to open path '%s'", plugin_dir_path)
                return nil
            end

            local re_plugins = fio.pathjoin(plugin_dir_path, '*.lua')
            local plugins = fio.glob(re_plugins)
            local plugin_cnt = #plugins

            logger:debug("found %d plugin files", plugin_cnt)

            package.loaded['ctl'] = self:plugin_api()
            for n, file in ipairs(plugins) do
                file = fio.abspath(file)
                logger:debug("loading plugin %s '%s'",
                             plugin_count_len(n, plugin_cnt),
                             file)
                load_sandboxed(file, {}, 'plugins')
            end
            package.loaded['ctl'] = nil
        end,
        plugin_api = function(self)
            return setmetatable(fun.iter(self):tomap(), {
                __index = {
                    register_library = register_library,
                    register_alias   = register_alias,
                    register_config  = register_config
                },
            })
        end,
        public_api = function(self)
            return setmetatable(fun.iter(self):tomap(), {
                __index = {
                    get_config = get_config
                },
            })
        end,
        usage = function(self, opts)
            opts = opts or {}
            opts.detailed = opts.detailed or false
            opts.depth    = opts.depth    or 0
            opts.header   = opts.header   or false

            if self.command ~= nil then
                logger:error("Unknown library or command name '%s'",
                             self.command)
                logger:error("")
            end

            logger:error("Tarantool client utility (%s)", _TARANTOOL)
            logger:error("Usage:")
            logger:error("")

            local sorted = fun.iter(self.libraries):map(function(name, val)
                return {val.description.weight or 0, name}
            end):totable();

            table.sort(sorted, function(l, r) return l[1] < r[1] end)
            opts.depth = opts.depth + 4
            opts.nested = true
            local lsorted = #sorted
            fun.iter(sorted):enumerate():each(function(n, val)
                local rv = self.libraries[val[2]]:usage(opts)
                if rv ~= nil then logger:write("") end
            end)
            opts.depth = opts.depth - 4
            return false
        end,
        run = function(self)
            self.command = table.remove(self.arguments, 1)
            if self.command == nil then
                return self:usage()
            end
            logger:debug('running %s', self.command)
            local alias = self.aliases[self.command]
            if alias ~= nil then
                local _, path = split_config(alias.path)
                table.insert(self.arguments, 1, path[2])
                self.command = path[1]
            end
            local wrapper = self.libraries[self.command]
            if wrapper == nil then
                return self:usage()
            end
            wrapper:run()
        end,
    }
})

local function find_defaults_file_user()
    local user = user_get()
    logger:debug('user with uid "%d" is used', user.uid)
    if user.uid ~= 0 then
        -- check in current directory
        local defaults = fio.pathjoin(fio.cwd(), '.tarantoolctl')
        logger:debug('defaults file: trying to find "%s"', defaults)
        if fio.stat(defaults) then
            return true, defaults
        end
        -- check in home directory
        defaults = os.getenv('HOME')
        if defaults ~= nil then
            defaults = fio.pathjoin(defaults, '.config/tarantool/tarantool')
            logger:debug('defaults file: trying to find "%s"', defaults)
            if fio.stat(defaults) then
                return true, defaults
            end
        end
    end
    -- we wern't been able to found tarantoolctl config in local/home
    -- directories (or we're 'root')
    return false, nil
end

local function find_defaults_file()
    -- try to find local/user configuration
    local user, defaults = find_defaults_file_user()
    if user == false then
        -- try to find system-wide configuration
        defaults = DEFAULT_DEFAULTS_PATH
        logger:debug('defaults file: trying to find "%s"', defaults)
        if not fio.stat(defaults) then
            defaults = nil
        end
    end

    if defaults == nil then
        logger:debug("can't find defaults file.")
    else
        logger:debug('using "%s" as defaults file', defaults)
    end
    -- no defaults path, assume defaults
    return user, defaults
end

local function is_linkmode(program_name)
    return not (fio.basename(program_name, '.lua') == DEFAULT_WRAPPER_NAME)
end

local function runner(tctl)
    -- make copy of arguments for modification
    tctl.executable   = arg[-1]
    tctl.program_name = arg[ 0]
    tctl.arguments    = argparse(arg)
    tctl.verbosity    = tctl.arguments.v
    if type(tctl.verbosity) ~= 'table' then
        tctl.verbosity = {tctl.verbosity}
    end
    tctl.verbosity    = #tctl.verbosity
    tctl.help         = ((tctl.arguments.h or tctl.arguments.help) and true) or false
    tctl.linkmode     = is_linkmode(tctl.program_name)

    -- we shouldn't throw errors until this place.
    -- output before that point is kinda buggy
    logger.verbosity = tctl.verbosity

    tctl.usermode, tctl.defaults = find_defaults_file()

    tctl.cfg:register('plugin_path', 'string', yaml.NULL)

    tctl:load_defaults(tctl.defaults)
    tctl:load_plugins(DEFAULT_PLUGIN_PATH)
    local plugin_path = tctl.cfg:get('plugin_path')
    if plugin_path ~= nil then
        tctl:load_plugins(plugin_path)
    end

    tarantoolctl:run()
end

if is_main() then
    execute_wrapped(runner, tarantoolctl, arg)
else
    -- return table for testing
    return {}
end
