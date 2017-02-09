local tntctl = require('ctl')
local logger = require('ctl.log')
local utils  = require('ctl.utils')

local ffi     = require('ffi')
local fio     = require('fio')
local yaml    = require('yaml')
local errno   = require('errno')
local fiber   = require('fiber')
local netbox  = require('net.box')
local socket  = require('socket')
local console = require('console')

ffi.cdef[[
    typedef int pid_t;
    int kill(pid_t pid, int sig);
]]

local DEFAULT_TARANTOOLCTL_NAME = 'cli'
local TIMEOUT_INFINITY = 100 * 365 * 86400

-- return linkmode, instance_name
-- return nil in case of error
local function find_instance_name(ctl)
    local instance_name = fio.basename(ctl.arguments[1], '.lua')
    if instance_name ~= nil then
        table.remove(ctl.arguments, 1)
        return false, instance_name
    end
    instance_name = ctl.program_name
    if type(instance_name) == 'string' and
       fio.basename(instance_name, '.lua') ~= DEFAULT_TARANTOOLCTL_NAME then
        local stat = fio.lstat(instance_name)
        if stat == nil then
            logger:syserror("failed to stat file '%s'", instance_name)
            return nil
        end
        if not stat:is_link() then
            logger:error("expected '%s' to be symlink", instance_name)
            return nil
        end
        return true, fio.basename(ctl.program_name, '.lua')
    end
    return nil
end

local function control_prepare_context(ctl, ctx)
    ctx = ctx or {}
    ctx.usermode     = ctl.usermode
    ctx.default_cfg  = {
        pid_file  = ctl:get_config('default_cfg.pid_file' ),
        wal_dir   = ctl:get_config('default_cfg.wal_dir'  ),
        snap_dir  = ctl:get_config('default_cfg.snap_dir' ),
        vinyl_dir = ctl:get_config('default_cfg.vinyl_dir'),
        logger    = ctl:get_config('default_cfg.logger'   ),
    }
    ctx.instance_dir = ctl:get_config('instance_dir')

    ctx.linkmode, ctx.instance_name = find_instance_name(ctl)
    if ctx.linkmode == nil then
        logger:error('Expected to find instance name, got nothing')
        return false
    end
    ctx.pid_file_path = ctx.default_cfg.pid_file
    ctx.console_sock_path = fio.pathjoin(
        ctx.pid_file_path,
        ctx.instance_name .. '.control'
    )
    ctx.console_sock = 'unix/:' .. ctx.console_sock_path
    ctx.instance_path = fio.pathjoin(
        ctx.instance_dir,
        ctx.instance_name .. '.lua'
    )
    if not fio.stat(ctx.instance_path) then
        logger:error("instance '%s' isn't found in %s",
                     ctx.instance_name .. '.lua',
                     ctx.instance_dir)
        return false
    end
    ctx.default_cfg.pid_file = fio.pathjoin(
        ctx.pid_file_path,
        ctx.instance_name .. '.pid'
    )
    ctx.default_cfg.logger = fio.pathjoin(
        ctx.default_cfg.logger,
        ctx.instance_name .. '.log'
    )

    if not ctx.usermod then
        ctx.username = ctl:get_config('default_cfg.username')
        local user_info = utils.user_get(ctx.username)
        if user_info == nil then
            logger:error_xc('failed to find user "%s"', ctx.username)
        end
        if user_info.group == nil then
            logger:error_xc('failed to find group of user "%s"', ctx.username)
        end
        ctx.groupname = user_info.group.name
    end
    return true
end

--------------------------------------------------------------------------------

local function read_file(filename)
    local file = fio.open(filename, {'O_RDONLY'})
    if file == nil then
        return nil
    end

    local buf = {}
    local i = 1
    while true do
        buf[i] = file:read(1024)
        if buf[i] == nil then
            return nil
        elseif buf[i] == '' then
            break
        end
        i = i + 1
    end
    return table.concat(buf)
end

local function stdin_isatty()
    return ffi.C.isatty(0) == 1
end

local function execute_remote(uri, code)
    local remote = netbox.connect(uri, {
        console = true, connect_timeout = TIMEOUT_INFINITY
    })
    if remote == nil then
        return nil
    end
    return true, remote:eval(code)
end

local function check_file(path)
    local rv, err = loadfile(path)
    if rv == nil then
        return err
    end
    return nil
end

-- shift argv to remove 'tarantoolctl' from arg[0]
local function shift_argv(arg, argno, argcount)
    local new_arg = {}
    for i = argno, 128 do
        if arg[i + argcount] == nil then
            break
        end
        new_arg[i] = arg[i + argcount]
    end
    arg = new_arg
end

-- Removes leading and trailing whitespaces
local function string_trim(str)
    return str:gsub("^%s*(.-)%s*$", "%1")
end

local function logger_parse(logstr)
    -- syslog
    if logstr:find("syslog:") then
        logstr = string_trim(logstr:sub(8))
        local args = {}
        logstr:gsub("([^,]+)", function(keyval)
            keyval:gsub("([^=]+)=([^=]+)", function(key, val)
                args[key] = val
            end)
        end)
        return 'syslog', args
    -- pipes
    elseif logstr:find("pipe:")   then
        logstr = string_trim(logstr:sub(6))
        return 'pipe', logstr
    elseif logstr:find("|")       then
        logstr = string_trim(logstr:sub(2))
        return 'pipe', logstr
    -- files
    elseif logstr:find("file:")   then
        logstr = string_trim(logstr:sub(6))
        return 'file', logstr
    else
        logstr = string_trim(logstr)
        return 'file', logstr
    end
end

local function syserror_format(fmt, ...)
    local stat = true
    if select('#', ...) > 0 then
        stat, fmt = pcall(string.format, fmt, ...)
    end
    if stat == false then
        error(fmt, 2)
    end
    return string.format('[errno %s] %s: %s', errno(), fmt, errno.strerror())
end

-- It's not 100% result guaranteed function, but it's ok for most cases
-- Won't help in multiple race-conditions
-- Returns nil if tarantool isn't started,
-- Returns PID if tarantool isn't started
-- Returns false, error if error occured
local function check_start(pid_file)
    logger:debug('Checking Tarantool with "%s" pid_file', pid_file)
    local fh = fio.open(pid_file, 'O_RDONLY')
    if fh == nil then
        if errno() == errno.ENOENT then
            return nil
        end
        return false, syserror_format("failed to open pid_file %s", pid_file)
    end

    local raw_pid = fh:read(64); fh:close()
    local pid     = tonumber(raw_pid)

    if pid == nil or pid <= 0 then
        return false, string.format(
            "bad contents of pid file %s: '%s'",
            pid_file, raw_pid
        )
    end

    if ffi.C.kill(pid, 0) < 0 then
        if errno() == errno.ESRCH then
            return nil
        end
        return false, syserror_format("kill of %d failed", pid)
    end
    return pid
end

-- Additionally check that we're able to write into socket
local function check_start_full(socket_path, pid_file)
    local stat, pid_check = check_start(pid_file)
    if stat == nil or stat == false then
        return stat, pid_check
    end

    if not fio.stat(socket_path) then
        return false, "Tarantool process exists, but control socket doesn't"
    end
    local s = socket.tcp_connect('unix/', socket_path)
    if s == nil then
        return false, syserror_format(
            "Tarantool process exists, but connection to console socket failed"
        )
    end

    local check_cmd = "return 1\n"
    if s:write(check_cmd) == -1 then
        return false, syserror_format(
            "failed to write %s bytes to control socket", check_cmd
        )
    end
    if s:read({ '[.][.][.]' }, 2) == -1 then
        return false, syserror_format("failed to read until delimiter '...'")
    end

    return stat
end

local function mkdir(ctx, dir)
    logger:write("recreating directory '%s'", dir)
    if not fio.mkdir(dir, tonumber('0750', 8)) then
        logger:syserror("failed mkdir '%s'", dir)
        return false
    end

    if not ctx.usermode and not fio.chown(dir, ctx.username, ctx.groupname) then
        logger:syserror("failed chown (%s, %s, %s)", ctx.username,
                        ctx.groupname, dir)
        return false
    end
    return false
end

local function mk_default_dirs(ctx, cfg)
    local init_dirs = {
        fio.dirname(cfg.pid_file),
        cfg.wal_dir,
        cfg.snap_dir,
        cfg.vinyl_dir,
    }
    local log_type, log_args = logger_parse(cfg.logger)
    if log_type == 'file' then
        table.insert(init_dirs, fio.dirname(log_args))
    end
    for _, dir in ipairs(init_dirs) do
        if not fio.stat(dir) and not mkdir(ctx, dir) then
            return false
        end
    end
    return true
end

local function wrapper_cfg_closure(ctx)
    local orig_cfg    = box.cfg
    local default_cfg = ctx.default_cfg

    return function(cfg)
        for i, v in pairs(default_cfg) do
            if cfg[i] == nil then
                cfg[i] = v
            end
        end

        -- force these startup options
        cfg.pid_file = default_cfg.pid_file
        if os.getenv('USER') ~= default_cfg.username then
            cfg.username = default_cfg.username
        else
            cfg.username = nil
        end
        if cfg.background == nil then
            cfg.background = true
        end

        if mk_default_dirs(ctx, cfg) == false then
            logger:error_xc('failed to create instance directories')
        end
        local success, data = pcall(orig_cfg, cfg)
        if not success then
            logger:error("Configuration failed: %s", data)
            if type(cfg) ~= 'function' then
                local log_type, log_args = logger_parse(cfg.logger)
                if log_type == 'file' and fio.stat(log_args) then
                    os.execute('tail -n 10 ' .. log_args)
                end
            end
            os.exit(1)
        end

        fiber.name(ctx.instance_name)
        logger:write("Run console at '%s'", ctx.console_sock_path)
        console.listen(ctx.console_sock)
        -- gh-1293: members of `tarantool` group should be able to do `enter`
        local mode = '0664'
        if not fio.chmod(ctx.console_sock_path, tonumber(mode, 8)) then
            logger:syserror("can't chmod(%s, %s)", ctx.console_sock_path, mode)
        end

        return data
    end
end

local function start(ctx)
    local function basic_start(ctx)
        logger:write("Starting instance '%s'...", ctx.instance_name)
        local err = check_file(ctx.instance_path)
        if err ~= nil then
            logger:error_xc("Failed to check instance file '%s'", err)
        end
        logger:debug("Instance file is OK")
        local pid, stat = check_start(ctx.default_cfg.pid_file)
        if type(pid) == 'number' then
            logger:error_xc("The daemon is already running with PID %s", pid)
        elseif pid == false then
            logger:error("Failed to determine status of instance '%s'",
                         ctx.instance_name)
            logger:error_xc(stat)
        end
        logger:debug("Instance '%s' wasn't started before", ctx.instance_name)
        box.cfg = wrapper_cfg_closure(ctx)
        require('title').update{
            script_name = ctx.instance_path,
            __defer_update = true
        }
        shift_argv(arg, 0, 2)
        local success, data = dofile(ctx.instance_path)
        -- if load fails - show last 10 lines of the log file and exit
        if not success then
            return 1
        end
        return 0
    end

    local stat, rv = pcall(basic_start, ctx)
    if stat == false or (type(rv) == 'number' and rv ~= 0) then
        logger:error("Failed to start Tarantool instance '%s'", ctx.instance_name)
        if type(rv) == 'string' then
            if rv:match('Please call box.cfg') then
                local _, rvt = utils.string_split(rv, '\n')
                rv = rvt[1]
            end
            local rv_debug = nil
            if rv:match(':%d+: ') then
                rv_debug, rv = rv:match('(.+:%d+): (.+)')
            end
            logger:debug("Error occured at %s", rv_debug)
            logger:error(rv)
        end
        if type(box.cfg) ~= 'function' then
            local log_type, log_args = logger_parse(ctx.default_cfg.logger)
            if log_type == 'file' and fio.stat(log_args) then
                os.execute('tail -n 10 ' .. log_args)
            end
        end
        return true
    end
    return false
end

local function stop(ctx)
    local function basic_stop(ctx)
        logger:write("Stopping instance '%s'...", ctx.instance_name)
        local pid_file = ctx.default_cfg.pid_file

        if fio.stat(pid_file) == nil then
            logger:write("Process is not running (pid: %s)", pid_file)
            return 0
        end

        local f = fio.open(pid_file, 'O_RDONLY')
        if f == nil then
            logger:syserror_xc("failed to read pid file %s", pid_file)
        end

        local raw_pid = f:read(64); f:close()
        local pid     = tonumber(raw_pid)

        if pid == nil or pid <= 0 then
            logger:error_xc("bad contents of pid file %s: '%s'",
                            pid_file, raw_pid)
        end

        if ffi.C.kill(pid, 15) < 0 then
            logger:syserror("failed to kill process %d", pid)
        end

        if fio.stat(pid_file) then
            fio.unlink(pid_file)
        end
        if fio.stat(ctx.console_sock_path) then
            fio.unlink(ctx.console_sock_path)
        end
        return 0
    end

    local stat, rv = pcall(basic_stop, ctx)
    if stat == false or (type(rv) == 'number' and rv ~= 0) then
        logger:error("Failed to stop Tarantool instance '%s'",
                     ctx.instance_name)
        if type(rv) == 'string' then
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

local function restart(ctx)
    local function basic_restart(ctx)
        local err = check_file(ctx.instance_path)
        if err ~= nil then
            logger:error_xc("Failed to check instance file '%s'", err)
        end
        if not stop(ctx) then
            return 1
        end
        fiber.sleep(1)
        if not start(ctx) then
            return 1
        end
        return 0
    end

    local stat, rv = pcall(basic_restart, ctx)
    if stat == false or (type(rv) == 'number' and rv ~= 0) then
        logger:error("Failed to restart Tarantool instance '%s'",
                     ctx.instance_name)
        if type(rv) == 'string' then
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

local function logrotate(ctx)
    local function basic_logrotate(ctx)
        logger:write("Rotating log of Tarantool instance '%s'...",
                     ctx.instance_name)
        local stat, pid_check = check_start_full(
            ctx.console_sock_path, ctx.default_cfg.pid_file
        )
        if stat == nil then
            logger:error_xc("instance '%s' isn't started", ctx.instance_name)
        elseif stat == false then
            logger:error("Failed to determine status of instance '%s'",
                         ctx.instance_name)
            logger:error_xc(pid_check)
        end

        local s = socket.tcp_connect('unix/', ctx.console_sock_path)
        if s == nil then
            logger:syserror_xc("failed to connect to instance '%s'",
                               ctx.instance_name)
        end

        local rotate_cmd = [[
            require('log'):rotate()
            require('log').info("Rotate log file")
        ]]
        if s:write(rotate_cmd) == -1 then
            logger:syserror_xc("failed to write %s bytes", #rotate_cmd)
        end
        if s:read({ '[.][.][.]' }, 2) == -1 then
            logger:syserror_xc("failed to read until delimiter '...'")
        end
        return 0
    end

    local stat, rv = pcall(basic_logrotate, ctx)
    if stat == false or (type(rv) == 'number' and rv ~= 0) then
        logger:error("Failed to rotate log of instance '%s'",
                     ctx.instance_name)
        if type(rv) == 'string' then
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

local function status(ctx)
    local pid_file = ctx.default_cfg.pid_file
    local console_sock = ctx.console_sock_path

    if fio.stat(pid_file) == nil then
        if errno() == errno.ENOENT then
            logger:write(
                '%s is stopped (pid file does not exist)',
                ctx.instance_name
            )
            return false
        end
        logger:syserror("can't access pid file %s: %s", pid_file)
    end

    if fio.stat(console_sock) == nil and errno() == errno.ENOENT then
        logger:write(
            "pid file exists, but the control socket (%s) doesn't",
            console_sock
        )
        return false
    end

    local s = socket.tcp_connect('unix/', console_sock)
    if s == nil then
        if errno() ~= errno.EACCES then
            logger:syserror("can't access control socket '%s'", console_sock)
            return false
        end
        return true
    end
    s:close()

    logger:write('%s is running (pid: %s)', ctx.instance_name, pid_file)
    return true
end

local function eval(ctx)
    local function basic_eval(ctx)
        local console_sock_path = ctx.console_sock_path
        local filename = table.remove(ctx.positional_arguments, 1)
        local code = nil
        if filename == nil then
            if stdin_isatty() then
                -- TODO: we need to call usage here
                logger:error_xc('usage')
            end
            code = io.stdin:read("*a")
        else
            code = read_file(filename)
            if code == nil then
                logger:syserror_xc("failed to open '%s'", filename)
            end
        end

        assert(code ~= nil, "Check that we've successfully loaded file")

        if fio.stat(console_sock_path) == nil then
            logger:error_xc(
                "pid file exists, but the control socket (%s) doesn't",
                console_sock_path
            )
        end

        local status, full_response = execute_remote(console_sock_path, code)
        if status == false then
            logger:error_xc(
                "control socket exists, but tarantool doesn't listen on it"
            )
        end
        local error_response = yaml.decode(full_response)[1]
        if type(error_response) == 'table' and error_response.error then
            logger:error_xc(error_response.error)
        end

        logger:write(full_response)
        return 0
    end

    local stat, rv = pcall(basic_eval, ctx)
    if stat == false or (type(rv) == 'number' and rv ~= 0) then
        if type(rv) == 'string' then
            if rv:match('usage') then
                logger:error_xc('usage')
            end
            logger:error("Failed eval command on instance '%s'",
                        ctx.instance_name)
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

local function enter(ctx)
    local console_sock_path = ctx.console_sock_path
    if fio.stat(console_sock_path) == nil then
        logger:error("Failed to enter into instance '%s'", ctx.instance_name)
        logger:syserror("can't connect to %s", console_sock_path)
        if not ctx.usermode and errno() == errno.EACCES then
            logger:error("please, add $USER to group '%s' with command",
                            ctx.group_name)
            logger:error('usermod -a -G %s $USER', ctx.group_name)
        end
        return false
    end

    local cmd = string.format(
        "require('console').connect('%s', { connect_timeout = %s })",
        ctx.console_sock, TIMEOUT_INFINITY
    )

    console.on_start(function(self) self:eval(cmd) end)
    console.on_client_disconnect(function(self) self.running = false end)
    console.start()
    return true
end

local function check(ctx)
    logger:error("Checking instance file '%s'...", ctx.instance_path)
    local rv = check_file(ctx.instance_path)
    if rv ~= nil then
        logger:write("Failed to check instance file: %s", ctx.instance_path)
        return false
    end
    logger:write("Instance file is OK")
    return true
end

tntctl:register_config('default_cfg.pid_file' , 'string', '/var/run/tarantool'              )
tntctl:register_config('default_cfg.wal_dir'  , 'string', '/var/lib/tarantool'              )
tntctl:register_config('default_cfg.snap_dir' , 'string', '/var/lib/tarantool'              )
tntctl:register_config('default_cfg.vinyl_dir', 'string', '/var/lib/tarantool'              )
tntctl:register_config('default_cfg.logger'   , 'string', '/var/lib/tarantool'              )
tntctl:register_config('default_cfg.username' , 'string', 'tarantool'                       )
tntctl:register_config('instance_dir'         , 'string', '/etc/tarantool/instances.enabled')

local control_library = tntctl:register_library('control')

control_library:register_prepare(control_prepare_context)

control_library:register_method('start',     start    , {
    header = "%s start <instance_name>",
    linkmode = "%s start",
    description = [=[
    start Tarantool instance if it's not already started.
    Tarantool instance should be maintained using tarantoolctl only.
    ]=],
    weight = 10,
})
control_library:register_method('stop',      stop     , {
    header = "%s stop <instance_name>",
    linkmode = "%s stop",
    description = [=[
    stop Tarantool instance if it's not already stopped.
    ]=],
    weight = 20,
})
control_library:register_method('restart',   restart  , {
    header = "%s restart <instance_name>",
    linkmode = "%s restart",
    description =
    [=[
    stop and start Tarantool instance (if it's already
    started, fail otherwise)
    ]=],
    weight = 40,
})
control_library:register_method('logrotate', logrotate, {
    header = "%s logrotate <instance_name>",
    linkmode = "%s logrotate",
    description =
    [=[
    rotate log of started Tarantool instance. Works only
    if logging is set into file. Pipe/Syslog aren't supported.
    ]=],
    weight = 50,
})
control_library:register_method('status',    status   , {
    header = "%s status <instance_name>",
    linkmode = "%s status",
    description = [=[
    show status of Tarantool instance. (started/stopped)
    ]=],
    weight = 30,
})
control_library:register_method('eval',      eval     , {
    header = {
        "%s eval <instance_name> <lua_file>",
        "<command> | %s eval <instance_name>"
    },
    linkmode = {
        "%s eval <lua_file>",
        "<command> | %s eval"
    },
    description =
    [=[
    evaluate local file on Tarantool instance (if it's
    already started, fail otherwise)
    ]=],
    weight = 70,
})
control_library:register_method('enter',     enter    , {
    header = "%s enter <instance_name>",
    linkmode = "%s enter",
    description =
    [=[
    enter interactive Lua console of instance.
    ]=],
    weight = 65,
})
control_library:register_method('check',     check    , {
    header = "%s check <instance_name>",
    linkmode = "%s check",
    description =
    [=[
    Check instance script for syntax errors
    ]=],
    weight = 60,
})

tntctl:register_alias('start',     'control.start'    )
tntctl:register_alias('stop',      'control.stop'     )
tntctl:register_alias('restart',   'control.restart'  )
tntctl:register_alias('logrotate', 'control.logrotate')
tntctl:register_alias('status',    'control.status'   )
tntctl:register_alias('eval',      'control.eval'     )
tntctl:register_alias('reload',    'control.eval'     , {
    deprecated = true
})
tntctl:register_alias('enter',     'control.enter'    )
tntctl:register_alias('check',     'control.check'    )

local function connect(ctx)
    local function basic_connect(ctx)
        ctx.remote_host = table.remove(ctx.positional_arguments, 1)
        if ctx.remote_host == nil then
            logger:error_xc('usage')
        end
        if not stdin_isatty() then
            local code = io.stdin:read("*a")
            if code == nil then
                logger:error_xc('usage')
            end
            local status, full_response = execute_remote(ctx.remote_host, code)
            if not status then
                logger:error_xc('failed to connect to tarantool')
            end
            local error_response = yaml.decode(full_response)[1]
            if type(error_response) == 'table' and error_response.error then
                logger:error("Error, while executing remote command:")
                logger:write(error_response.error)
            end
            logger:write(full_response)
            return 0
        end
        -- Otherwise we're starting console
        console.on_start(function(self)
            local status, reason = pcall(console.connect,
                ctx.remote_host, { connect_timeout = TIMEOUT_INFINITY }
            )
            if not status then
                self:print(reason)
                self.running = false
            end
        end)

        console.on_client_disconnect(function(self) self.running = false end)
        console.start()
        return 0
    end

    local stat, rv = pcall(basic_connect, ctx)
    if stat == false or (type(rv) == 'number' and rv ~= 0) then
        logger:error("Failed connecting to remote instance '%s'",
                     ctx.remote_host)
        if type(rv) == 'string' then
            if rv:match('usage') then
                logger:error_xc('usage')
            end
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

local function console_prepare_context(ctl, ctx)
end

local console_library = tntctl:register_library('console')
console_library:register_prepare(console_prepare_context)

console_library:register_method('connect', connect, {
    header = {
        "%s connect <instance_uri>",
        "<command> | %s connect <instance_uri>"
    },
    description =
    [=[
    Connect to Tarantool instance on admin/console port.
    Supports both TCP/Unix sockets.
    ]=],
    weight = 80,
})
tntctl:register_alias('connect', 'console.connect')
