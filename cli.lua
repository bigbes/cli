#!/usr/bin/env tarantool

local fio   = require('fio')
local fun   = require('fun')
local json  = require('json')
local yaml  = require('yaml').new()
local errno = require('errno')

yaml.cfg{
    encode_invalid_numbers = true,
    encode_load_metatable = true,
    encode_use_tostring = true,
    encode_invalid_as_nil = true,
}

-- basic types
local types = {
  STRING = 0,
  INT    = 1,
  FLOAT  = 2,
  BOOL   = 3
}

-- arguments (positional one)
-- name     [result name]
-- nargs    [default=1],     -1 for all that's left. may be only one
-- type     [default=STRING] or function
-- callback [default=nil]    or function
-- required [default=false]
--
-- tail arguments (empty or not, converted or not)


-- logger
--   || API:
--   || write, debug, error (3 levels, for now)
--   ==
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
--   || Public API:
--   || !! absent
--   \/
-- method
--   || Plugin API:
--   || !! absent
--   || Public API:
--   || * config_get
--   ==

--------------------------------------------------------------------------------
--                            logging abstraction                             --
--------------------------------------------------------------------------------

local function logger_new()
    local function logger_closure(prefix)
        return function(self, fmt, ...)
            assert(type(fmt) == 'string')
            if select('#', ...) > 0 then
                fmt = fmt:format(...)
            end
            self.stream:write(prefix, fmt, '\n')
        end
    end

    local logger = setmetatable({
        stream = io.stderr
    }, {
        __index = {
            write = logger_closure(''),
            debug = logger_closure('debug | '),
            error = logger_closure('error | '),
            syserror = function(self, fmt, ...)
                if select('#', ...) > 0 then
                    fmt = fmt:format(...)
                end
                self.stream:write(
                    string.format(
                        ' error | [errno %d] %s: %s\n',
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
                -- print backtrace
                self:write_traceback('debug', level)
                -- format error message
                local stat = true
                if select('#', ...) >= fmt_pos then
                    stat, fmt = pcall(
                        string.format,
                        select(fmt_pos - 1, ...)
                    )
                end
                error(fmt, stat == false and level or 2)
            end,
            -- :syserror_xc([level,] format, ...)
            syserror_xc = function(self, ...)
                local fmt_pos, level = 2, 2
                local fmt = ...
                if type(fmt) == 'number' then
                    fmt_pos = 3
                    level, fmt = ...
                end
                -- print backtrace
                self:write_traceback('debug', level)
                -- format error message
                fmt = '[errno %d] ' .. fmt .. ': %s'
                local stat, fmt = pcall(
                    string.format,
                    fmt, errno(), select(fmt_pos, ...), errno.strerror()
                )
                error(fmt, stat == false and level or 2)
            end
        }
    })
    package.loaded['ctl.log'] = logger
    return logger
end

local logger = logger_new()

--------------------------------------------------------------------------------
--                                 Utilities                                  --
--------------------------------------------------------------------------------

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
        err = err or '<none>'
        logger:error('')
        logger:error('Error catched: %s', err)
        if errno() ~= 0 then
            logger:error('[errno %d] %s', errno(), errno.strerror())
        end
        logger:write_traceback('error', 3)
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

--------------------------------------------------------------------------------
--                               Configuration                                --
--------------------------------------------------------------------------------

local function tarantoolctl_cfg_new()
    return setmetatable({
        __vals = {}, __defs = {}
    }, {
        __index = {
            register = function(self, name, tp, default)
                assert(type(default) ~= 'nil')
                self.__defs[name] = {tp, default}
            end,
            get = function(self, name)
                if self.__vals[name] == nil then
                    local default = self.__defs[name][2]
                    if is_callable(default) then
                        default = default()
                    end
                    self.__vals[name] = default
                end
                local tp = self.__defs[name][1]
                if type(self.__vals[name]) ~= tp then
                    logger:error('config "%s": expected type "%s", got "%s"',
                                        name, tp, type(self.__vals[name]))
                    return nil
                end
                return self.__vals[name]
            end,
            load_dictionary = function(self, name, value)
                -- assume, that dicts have only string keys (for now)
                name = name == nil and '' or name .. '.'
                for subname, subvalue in pairs(value) do
                    subname = name .. subname
                    if type(subvalue) == 'table' then
                        self:load_dictionary(subname, subvalue)
                    else
                        self.__vals[subname] = subvalue
                    end
                end
            end,
            load = function(self, default_path)
                local result_environment = {}
                load_sandboxed(default_path, result_environment, 'defaults')
                self:load_dictionary(nil, result_environment)
            end
        },
    })
end

--------------------------------------------------------------------------------
--                         cli arguments abstractions                         --
--------------------------------------------------------------------------------

--[[
local function parse_param_prefix(param)
    if param == nil then return nil end
    local is_long  = (param:find("^[-][-]") ~= nil)
    local is_short = not is_long and (param:find("^[-]") ~= nil)
    local is_dash  = is_short and (param:find("^[-]$") ~= nil)
    return is_long, is_short, is_dash
end

local function result_set_add(t_out, key, val)
    if val == nil then
        table.insert(t_out, key)
    elseif t_out[key] == nil then
        t_out[key] = val
    elseif type(t_out[key]) == 'table' then
        table.insert(t_out[key], val)
    else
        t_out[key] = {t_out[key], val}
    end
end

local function parameters_parse(t_in)
    local t_out, t_in = {}, t_in or {}
    local skip_param = false
    for i, v in ipairs(t_in) do
        -- we've used this parameter as value
        if skip_param == true then
            skip_param = false
            goto nextparam
        end
        local is_long, is_short, is_dash = parse_param_prefix(v)
        if not is_dash and is_short then
            local commands = v:sub(2)
            if not commands:match("^[%a]+$") then
                logger:error_xc("bad argument #%d (%s): ID not valid",
                                i, commands)
            end
            for id in v:sub(2):gmatch("%a") do
                result_set_add(t_out, id, true)
            end
        elseif is_long then
            local command = v:sub(3)
            if command:find('=') then
                local key, val = command:match("^([%a_][%w_-]+)%=(.*)$")
                if key == nil or val == nil then
                    logger:error_xc("bad argument #%d (%s): ID not valid",
                                    i, command)
                end
                result_set_add(t_out, key, val)
            else
                if not command:match("^([%a_][%w_-]+)$") then
                    logger:error_xc("bad argument #%d (%s): ID not valid",
                                    i, command)
                end
                local val = true
                do
                    -- in case next argument is value of this key (not --arg)
                    local next_arg = t_in[i + 1]
                    local is_long, is_short, is_dash = parse_param_prefix(next_arg)
                    if is_dash then
                        skip_param = true
                    elseif is_long == false and not is_short and not is_dash then
                        val = next_arg
                        skip_param = true
                    end
                end
                result_set_add(t_out, command, val)
            end
        else
            table.insert(t_out, v)
        end
::nextparam::
    end
    return t_out
end

local function convert_parameter_simple(name, convert_from, convert_to)
    if convert_to == 'number' then
        local converted = tonumber(convert_from)
        if converted == nil then
            error(
                ('Bad value for parameter %s. expected type %s, got "%s"')
                :format(name, convert_to, convert_from)
            )
        end
        return converted
    elseif convert_to == 'boolean' then
        if type(convert_from) ~= 'boolean' then
            error(
                ('Bad input for parameter "%s". Expected boolean, got "%s"')
                :format(name, convert_from)
            )
        end
    elseif convert_to == 'string' then
        if type(convert_from) ~= 'string' then
            error(
                ('Bad input for parameter "%s". Expected string, got "%s"')
                :format(name, convert_from)
            )
        end
    else
        error(
            ('Bad convertion format "%s" provided for %s')
            :format(convert_to, name)
        )
    end
    return convert_from
end

local function convert_parameter(name, convert_from, convert_to)
    if convert_to == nil then
        return convert_from
    end
    if convert_to:find('+') then
        convert_to = convert_to:sub(1, -2)
        if type(convert_from) ~= 'table' then
            convert_from = { convert_from }
        end
        convert_from = fun.iter(convert_from):map(function(v)
            return convert_parameter_simple(name, v, convert_to)
        end):totable()
    else
        if type(convert_from) == 'table' then
            convert_from = table.remove(convert_from)
        end
        convert_from = convert_parameter_simple(name, convert_from, convert_to)
    end
    return convert_from
end

-- options is array of {name, type, count, default}
local function convert_parameters(t_out, options)
    local lookup, unknown = {}, {}
    for _, v in ipairs(options) do
        if type(v) ~= 'table' then
            v = {v}
        end
        lookup[ v[1] ] = (v[2] or true)
    end
    for k, v in pairs(t_out) do
        if lookup[k] == nil and type(k) == "string" then
            table.insert(unknown, k)
        elseif type(lookup[k]) == 'string' then
            t_out[k] = convert_parameter(k, v, lookup[k])
        end
    end
    if #unknown > 0 then
        error(("unknown options: %s"):format(table.concat(unknown, ", ")))
    end
    return t_out
end

local function tarantool_args_new()
    return setmetatable({
        args = parameters_parse(args),
        definitions = {}
    }, {
        __index = {
            register = function(self, name, tp, default, module)
                local cfg = self.definitions[name]
                if cfg ~= nil then
                    logger:error('failed to register configuration value ' ..
                                 '"%s" by "%s"', name, module)
                    logger:error('already registered by "%s"', cfg.module)
                    return false
                end
                self.definitions[name] = {
                    name = name, type = tp, module = module,
                    default = default, required = required,
                }
                return true
            end,
            check = function(self)
            end,
            get = function(self, name)
            end
        }
    })
end
]]--

--------------------------------------------------------------------------------
--                        library/methods abstractions                        --
--------------------------------------------------------------------------------

local constructors = {
    library = nil,
    method = nil,
}

constructors.method = function(name, cb)
    return setmetatable({
        name = name,
        callback = cb
    }, {
        __index = {
            run = function(self)
                logger:debug("calling callback '%s'", self.name)
                self:callback()
                logger:debug("after callback '%s'",   self.name)
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

local function register_library(self, name)
    logger:debug("registering library '%s'", name)
    if self.libraries[name] ~= nil then
        logger:error("failted to register library. already exists")
        return nil
    end
    assert(self.libraries[name] == nil)

    local lib_instance = constructors.library(name)
    self.libraries[name] = lib_instance

    return lib_instance:plugin_api()
end

local function register_method(self, name, callback)
    logger:debug("registering method '%s'", name)
    assert(self.methods[name] == nil)

    local meth_instance = constructors.method(name, callback)
    self.methods[name] = meth_instance

    return meth_instance:plugin_api()
end

local function register_config(self, name, tp, default)
    logger:debug("registering configuration value '%s'", name)
    logger:debug("type '%s'. defaults to '%s'", tp,
                    json.encode(default))
    self.cfg:register(name, tp, default)
end

local function register_alias(self, name, dotted_path)
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
        logger:error("bad alias path '%s' (module '%s' not found)",
                     dotted_path, lname)
        return nil
    end
    local method = library.methods[mname]
    if method == nil then
        logger:error("bad alias path '%s' (module '%s' not found)",
                     dotted_path, lname)
        return nil
    end

    self.aliases[name] = method

    return method:plugin_api()
end

constructors.library = function(name)
    return setmetatable({
        name = name,
        methods = {},
    }, {
        __index = {
            plugin_api = function(self)
            return setmetatable(fun.iter(self):tomap(), {
                __index = {
                    register_method = register_method,
                }
            })
            end,
            public_api = function(self)
                return self
            end,
            usage = function(self)
            end,
            run = function(self, name, args)
                logger:debug('running %s with "%s" arguments', name, json.encode(args))
                local wrapper = self.methods[name] or self.libraries[name]
                if wrapper == nil then
                    return self:usage()
                end
                wrapper:run(table.remove(args, 1), args)
            end,
        }
    })
end

local tarantoolctl = setmetatable({
    libraries = {},
    methods = {},
    plugins = {},
    aliases = {},
    cfg  = tarantoolctl_cfg_new(),
    -- args = tarantoolctl_args_new(),
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

            local re_plugins = fio.pathjoin(plugin_dir_path, '*.lua')
            local plugins = fio.glob(re_plugins)
            local plugin_cnt = #plugins

            logger:debug("found %d plugin files", plugin_cnt)

            package.loaded['ctl'] = self:plugin_api()
            for n, file in ipairs(plugins) do
                file = fio.abspath(file)
                logger:debug("load plugin %s '%s'",
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
                }
            })
        end,
        public_api = function(self)
            return self
        end,
        usage = function(self)
        end,
        run = function(self, name, args)
            logger:debug('running %s with "%s" arguments', name, json.encode(args))
            local wrapper = (
                self.methods[name] or
                self.aliases[name] or
                self.libraries[name]
            )
            if wrapper == nil then
                return self:usage()
            end
            wrapper:run(table.remove(args, 1), args)
        end,
    }
})

local function runner(tctl, args)
    -- make copy of arguments for modification
    local args = fun.iter(args):totable()
    tctl.program_name = args[0]

    tctl:load_defaults('defaults.lua')
    tctl:load_plugins ('./plugins')

    tarantoolctl:run(table.remove(args, 1), args)
end

if is_main() then
    execute_wrapped(runner, tarantoolctl, arg)
else
    -- return table for testing
    return {}
end
