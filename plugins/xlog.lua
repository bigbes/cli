local tntctl = require('ctl')
local logger = require('ctl.log')
local utils  = require('ctl.utils')

local fio  = require('fio')
local json = require('json')
local xlog = require('xlog')
local yaml = require('yaml')
local netbox = require('net.box')
local argparse = require('internal.argparse').parse

-- we're using io.stdout here, because io.stderr is used by logger and we
-- need to differintiate between cat output and logging

local function find_space(sid, spaces)
    if type(spaces) == 'number' then
        return sid == spaces
    end
    local shown = false
    for _, v in ipairs(spaces) do
        if v == sid then
            shown = true
            break
        end
    end
    return shown
end

local write_lua_table = nil

-- escaped string will be written
local function write_lua_string(string)
    io.stdout:write("'")
    local pos, byte = 1, string:byte(1)
    while byte ~= nil do
        io.stdout:write(("\\x%x"):format(byte))
        pos = pos + 1
        byte = string:byte(pos)
    end
    io.stdout:write("'")
end

local function write_lua_value(value)
    if type(value) == 'string' then
        write_lua_string(value)
    elseif type(value) == 'table' then
        write_lua_table(value)
    else
        io.stdout:write(tostring(value))
    end
end

local function write_lua_fieldpair(key, val)
    io.stdout:write("[")
    write_lua_value(key)
    io.stdout:write("] = ")
    write_lua_value(val)
end

write_lua_table = function(tuple)
    io.stdout:write('{')
    local is_begin = true
    for key, val in pairs(tuple) do
        if is_begin == false then
            io.stdout:write(', ')
        else
            is_begin = false
        end
        write_lua_fieldpair(key, val)
    end
    io.stdout:write('}')
end

local function cat_lua_cb(record)
    io.stdout:write(('box.space[%d]'):format(record.BODY.space_id))
    local op = record.HEADER.type:lower()
    io.stdout:write((':%s('):format(op))
    if op == 'insert' or op == 'replace' then
        write_lua_table(record.BODY.tuple)
    elseif op == 'delete' then
        write_lua_table(record.BODY.key)
    elseif op == 'update' then
        write_lua_table(record.BODY.key)
        io.stdout:write(', ')
        write_lua_table(record.BODY.tuple)
    elseif op == 'upsert' then
        write_lua_table(record.BODY.tuple)
        io.stdout:write(', ')
        write_lua_table(record.BODY.operations)
    end
    io.stdout:write(')\n')
end

local function cat_yaml_cb(record)
    io.stdout:write(yaml.encode(record):sub(1, -6), '\n')
end

local function cat_json_cb(record)
    io.stdout:write(json.encode(record), '\n')
end

local cat_formats = setmetatable({
    yaml = cat_yaml_cb,
    json = cat_json_cb,
    lua  = cat_lua_cb,
}, {
    __index = function(self, cmd)
        error(("Unknown formatter '%s'"):format(cmd))
    end
})

local function cat(ctx)
    local function basic_cat(ctx)
        local options = ctx.keyword_arguments
        local from, to, spaces = options.from, options.to, options.space
        local show_system, cat_format = options['show-system'], options.format

        local format_cb   = cat_formats[cat_format]
        local is_printed  = false
        for id, file in ipairs(ctx.files) do
            logger:write("Processing file '%s'", file)
            for lsn, record in xlog.pairs(file) do
                local sid = record.BODY.space_id
                local is_filtered    = spaces ~= nil
                local is_system      = sid < 512 and show_system == false
                local isnt_specified = not (is_filtered and find_space(sid, spaces))
                if (lsn < from) or
                   (is_filtered and is_system and isnt_specified) or
                   (is_system and isnt_specified) then
                    -- pass this tuple
                elseif lsn >= to then
                    -- stop, as we've had finished reading tuple with lsn == to
                    -- and next lsn's will be bigger
                    break
                else
                    is_printed = true
                    format_cb(record)
                    io.stdout:flush()
                end
            end
            if options.format == 'yaml' and is_printed then
                is_printed = false
                io.stdout:write('...\n')
            end
        end
        return 0
    end

    local stat, rv = pcall(basic_cat, ctx)
    if stat == false or (type(rv) == 'number' and rv ~= 0) then
        if type(rv) == 'string' then
            if rv:match('usage') then
                logger:error_xc('usage')
            end
            logger:error("Failed to execute cat command")
            local rv_debug = nil
            if rv:match(':%d+: ') then
                rv_debug, rv = rv:match('(.+:%d+): (.+)')
            end
            logger:debug("Error occured at %s", rv_debug)
            logger:error(rv)
        end
        return false
    end
    return true
end

local function play(ctx)
    local function basic_play(ctx)
        local options = ctx.keyword_arguments
        local from, to, spaces = options.from, options.to, options.space
        local show_system = options['show-system']
        local uri = ctx.host

        local remote = netbox.new(uri)
        if not remote:wait_connected() then
            logger:error_xc("Failed to connect to host '%s'", uri)
        end
        for id, file in ipairs(ctx.files) do
            logger:write("Processing file '%s'", file)
            for lsn, record in xlog.pairs(file) do
                local sid = record.BODY.space_id
                local is_filtered    = spaces ~= nil
                local is_system      = sid < 512 and show_system == false
                local isnt_specified = not (is_filtered and find_space(sid, spaces))
                if (lsn < from) or
                   (is_filtered and is_system and isnt_specified) or
                   (is_system and isnt_specified) then
                    -- pass this tuple
                elseif lsn >= to then
                    -- stop, as we've had finished reading tuple with lsn == to
                    -- and next lsn's will be bigger
                    break
                else
                    local args, so = {}, remote.space[sid]
                    if so == nil then
                        error(("No space #%s, stopping"):format(sid))
                    end
                    table.insert(args, so)
                    table.insert(args, record.BODY.key)
                    table.insert(args, record.BODY.tuple)
                    table.insert(args, record.BODY.operations)
                    so[record.HEADER.type:lower()](unpack(args))
                end
            end
        end
        remote:close()
        return 0
    end

    local stat, rv = pcall(basic_play, ctx)
    if stat == false or (type(rv) == 'number' and rv ~= 0) then
        if type(rv) == 'string' then
            if rv:match('usage') then
                logger:error_xc('usage')
            end
            logger:error("Failed to execute play command")
            local rv_debug = nil
            if rv:match(':%d+: ') then
                rv_debug, rv = rv:match('(.+:%d+): (.+)')
            end
            logger:debug("Error occured at %s", rv_debug)
            logger:error(rv)
        end
        return false
    end
    return true
end

local function xlog_prepare_context(ctl, ctx)
    local function parameters_reparse()
        local function keyword_arguments_populate(ka)
            ka                = ka                or {}
            ka.from           = ka.from           or 0
            ka.to             = ka.to             or -1ULL
            ka['show-system'] = ka['show-system'] or false
            ka.format         = ka.format         or 'yaml'
            ka.force          = ka.force          or false
            return ka
        end
        local parameters = argparse(arg, {
            { 'space',       'number+'  },
            { 'show-system', 'boolean'  },
            { 'from',        'number'   },
            { 'to',          'number'   },
            { 'help',        'boolean'  },
            { 'format',      'string'   },
            { 'force',       'boolean'  },
            { 'v',           'boolean+' },
            { 'h',           'boolean'  }
        })
        local keyword_arguments = {}
        for k, v in pairs(parameters) do
            if type(k) ~= 'number' then
                keyword_arguments[k] = v
            end
        end
        return keyword_arguments_populate(keyword_arguments)
    end

    -- logger.stream = io.stderr
    ctx.keyword_arguments = parameters_reparse()

    if ctx.command == 'play' then
        local host = table.remove(ctx.positional_arguments, 1)
        if host == nil then
            logger:error('Empty URI is provided')
            return false
        end
        ctx.remote_host = host
    end
    ctx.files = {}
    for _, name in ipairs(ctx.positional_arguments) do
        if fio.stat(name) == nil then
            logger:error("File %s expected to be read, but can't be found")
            if ctx.keyword_arguments.force ~= true then
                return false
            end
        else
            table.insert(ctx.files, name)
        end
    end
    if #ctx.files == 0 then
        logger:error("No xlog/snap files are provided")
        return false
    end
    return true
end

local xlog_library = tntctl:register_library('xlog', { weight = 30 })
xlog_library:register_prepare('xlog', xlog_prepare_context)
xlog_library:register_method('cat', cat, {
    help = {
        description = [=[
            Show contents of snapshot/xlog files. Result is printed to stdout
        ]=],
        arguments = {
            {"--space=space_no ..", "Filter by space number. May be passed more than once." },
            {"--show-system",       "Show contents of system spaces"                        },
            {"--from=lsn-from",     "Ignore operation with LSN lower than lsn-from"         },
            {"--to=lsn-to",         "Show operations with LSN lower than lsn-to "           }
        },
        header = "%s cat <filename>.. [--space=space_no..] [--show-system] " ..
                 "[--from=from_lsn] [--to=to_lsn]",
    },
    exiting = true,
})
xlog_library:register_method('play', play, {
    help = {
        description = [=[
            Play contents of snapshot/xlog files on another Tarantool instance
        ]=],
        arguments = {
            {"--space=space_no ..", "Filter by space number. May be passed more than once." },
            {"--show-system",       "Play contents of system spaces"                        },
            {"--from=lsn-from",     "Ignore operation with LSN lower than lsn-from"         },
            {"--to=lsn-to",         "Play operations with LSN lower than lsn-to "           }
        },
        header = "%s play <instance_uri> <filename>.. [--space=space_no..] " ..
                 "[--show-system] [--from=lsn-from] [--to=lsn-to]",
    },
    exiting = true,
})
tntctl:register_alias('cat',  'xlog.cat' )
tntctl:register_alias('play', 'xlog.play')
