#!/usr/bin/env tarantool

--------------------------------------------------------------------------------
--                                  plugins                                   --
--------------------------------------------------------------------------------

local function plugin_ctl()
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
        int isatty(int fd);
    ]]

    local TIMEOUT_INFINITY = 100 * 365 * 86400

    local function stdin_isatty()
        return ffi.C.isatty(0) == 1
    end

    -- return linkmode, instance_name
    -- return nil in case of error
    local function find_instance_name(ctx, positional_arguments)
        local instance_name = nil
        if ctx.linkmode then
            instance_name = ctx.program_name
            local stat = fio.lstat(instance_name)
            if stat == nil then
                logger:syserror("failed to stat file '%s'", instance_name)
                return nil
            end
            if not stat:is_link() then
                logger:error("expected '%s' to be symlink", instance_name)
                return nil
            end
            return fio.basename(ctx.program_name, '.lua')
        end
        return fio.basename(table.remove(ctx.positional_arguments, 1), '.lua')
    end

    local function control_prepare_context(ctl, ctx)
        ctx = ctx or {}
        ctx.program_name = ctl.program_name
        ctx.usermode     = ctl.usermode
        ctx.linkmode     = ctl.linkmode
        ctx.default_cfg  = {
            pid_file  = ctl:get_config('default_cfg.pid_file' ),
            wal_dir   = ctl:get_config('default_cfg.wal_dir'  ),
            snap_dir  = ctl:get_config('default_cfg.snap_dir' ),
            vinyl_dir = ctl:get_config('default_cfg.vinyl_dir'),
            logger    = ctl:get_config('default_cfg.logger'   ),
        }
        ctx.instance_dir = ctl:get_config('instance_dir')

        ctx.instance_name = find_instance_name(ctx)
        if ctx.instance_name == nil then
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

        if ctx.command_name == 'eval' then
            ctx.eval_source = table.remove(ctx.positional_arguments, 1)
            if ctx.eval_source == nil and stdin_isatty() then
                logger:error("Error: expected source to evaluate, got nothing")
                return false
            end
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
        return true
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
            -- it may throw error, but we will catch it in start() function
            dofile(ctx.instance_path)
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
            local code = nil
            if not ctx.eval_source then
                code = io.stdin:read("*a")
            else
                code = read_file(ctx.eval_source)
                if code == nil then
                    logger:syserror_xc("failed to open '%s'", ctx.eval_source)
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
    control_library:register_prepare('control', control_prepare_context)
    control_library:register_method('start', start, {
        help = {
            description = [=[
                Start Tarantool instance if it's not already started. Tarantool
                instance should be maintained using tarantoolctl only
            ]=],
            header   = "%s start <instance_name>",
            linkmode = "%s start"
        },
        exiting = false,
    })
    control_library:register_method('stop', stop, {
        help = {
            description = [=[
                Stop Tarantool instance if it's not already stopped
            ]=],
            header   = "%s stop <instance_name>",
            linkmode = "%s stop",
        },
        exiting = true,
    })
    control_library:register_method('status', status, {
        help = {
            description = [=[
                Show status of Tarantool instance. (started/stopped)
            ]=],
            header   = "%s status <instance_name>",
            linkmode = "%s status",
        },
        exiting = true,
    })
    control_library:register_method('restart', restart, {
        help = {
            description = [=[
                Stop and start Tarantool instance (if it's already started, fail
                otherwise)
            ]=],
            header   = "%s restart <instance_name>",
            linkmode = "%s restart",
        },
        exiting = true,
    })
    control_library:register_method('logrotate', logrotate, {
        help = {
            description = [=[
                Rotate log of started Tarantool instance. Works only if logging is
                set into file. Pipe/Syslog aren't supported.
            ]=],
            header   = "%s logrotate <instance_name>",
            linkmode = "%s logrotate",
        },
        exiting = false,
    })
    control_library:register_method('check', check, {
        help = {
            description = [=[
                Check instance script for syntax errors
            ]=],
            header   = "%s check <instance_name>",
            linkmode = "%s check",
        },
        exiting = true,
    })
    control_library:register_method('enter', enter, {
        help = {
            description = [=[
                Enter interactive Lua console of instance
            ]=],
            header   = "%s enter <instance_name>",
            linkmode = "%s enter",
        },
        exiting = true,
    })
    control_library:register_method('eval', eval, {
        help = {
            description = [=[
                Evaluate local file on Tarantool instance (if it's already started,
                fail otherwise)
            ]=],
            header = {
                "%s eval <instance_name> <lua_file>",
                "<command> | %s eval <instance_name>"
            },
            linkmode = {
                "%s eval <lua_file>",
                "<command> | %s eval"
            },
        },
        exiting = true,
    })
    tntctl:register_alias('start',     'control.start'    )
    tntctl:register_alias('stop',      'control.stop'     )
    tntctl:register_alias('restart',   'control.restart'  )
    tntctl:register_alias('logrotate', 'control.logrotate')
    tntctl:register_alias('status',    'control.status'   )
    tntctl:register_alias('eval',      'control.eval'     )
    tntctl:register_alias('reload',    'control.eval'     , { deprecated = true })
    tntctl:register_alias('enter',     'control.enter'    )
    tntctl:register_alias('check',     'control.check'    )

    local function connect(ctx)
        local function basic_connect(ctx)
            if ctx.connect_code then
                local status, full_response = execute_remote(ctx.remote_host,
                                                            ctx.connect_code)
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
        if ctx.command_name == 'connect' then
            ctx.connect_endpoint = table.remove(ctx.positional_arguments, 1)
            if ctx.connect_endpoint == nil then
                logger:error("Expected URI to connect to")
                return false
            end
            if not stdin_isatty() then
                ctx.connect_code = io.stdin:read("*a")
                if not ctx.connect_code or ctx.connect_code == '' then
                    logger:error("Failed to read from stdin")
                    return false
                end
            else
                ctx.connect_code = nil
            end
        end
        return true
    end

    local console_library = tntctl:register_library('console', { weight = 20 })
    console_library:register_prepare('connect', console_prepare_context)
    console_library:register_method('connect', connect, {
        help = {
            description = [=[
                Connect to Tarantool instance on admin/console port. Supports both
                TCP/Unix sockets
            ]=],
            header = {
                "%s connect <instance_uri>",
                "<command> | %s connect <instance_uri>"
            },
        },
        exiting = true,
    })
    tntctl:register_alias('connect', 'console.connect')
end

local function plugin_xlog()
    local tntctl = require('ctl')
    local logger = require('ctl.log')
    local utils  = require('ctl.utils')

    local fio      = require('fio')
    local json     = require('json')
    local xlog     = require('xlog')
    local yaml     = require('yaml')
    local netbox   = require('net.box')
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
end

--------------------------------------------------------------------------------
--                                    ctl                                     --
--------------------------------------------------------------------------------

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
--   || * get_config
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

local function load_file_sandboxed(path, env, desc)
    path = fio.abspath(path)
    ufunc, msg = loadfile(path)
    if not ufunc then
        logger:error("Failed to load %s file '%s':", desc, path)
        logger:error(msg)
        return false
    end
    debug.setfenv(ufunc, setmetatable(env, { __index = _G }))
    local rval = { execute_wrapped(ufunc) }
    if not rval[1] then
        logger:error("Failed to execute %s file '%s':", desc, path)
        logger:error(rval[2])
        return false
    end
    return unpack(rval)
end

local function load_func_sandboxed(func, env, desc)
    debug.setfenv(func, setmetatable(env, { __index = _G }))
    local rval = { execute_wrapped(ufunc) }
    if not rval[1] then
        logger:error("Failed to execute '%s' function:", desc)
        logger:error(rval[2])
        return false
    end
    return unpack(rval)
end

local function deepcopy(orig)
    local orig_type = type(orig)
    local copy = orig
    if orig_type == 'table' then
        copy = {}
        for orig_key, orig_value in pairs(orig) do
            copy[orig_key] = deepcopy(orig_value)
        end
    end
    return copy
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
                load_file_sandboxed(default_path, result_environment, 'defaults')
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

local function usage_header()
    logger:error("Tarantool client utility (%s)", _TARANTOOL)
    logger:error("Usage:")
    logger:error("")
end

-- split long line into muple one's with max width of 80 charachters and
-- prepends with depth spaces
local function print_aligned(lines, depth)
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

local tctl_method_methods = {
    run = function(self, context)
        logger:debug("calling callback '%s'", self.name)
        local rv = execute_wrapped(self.callback, context)
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

        local header = self.help.header
        if tarantoolctl.linkmode then
            if not self.help.linkmode then
                return
            end
            header = self.help.linkmode
        end
        if type(header) ~= 'table' then
            header = { header }
        end
        for _, line in ipairs(header) do
            line = line:format(tarantoolctl.program_name)
            local is_first_line = false
            for _, line in ipairs(
                print_aligned(line, opts.depth)
            ) do
                if is_first_line then line = '    ' .. line end
                logger:write(line)
                is_first_line = true
            end
        end

        opts.detailed = opts.detailed or tarantoolctl.help
        if opts.detailed then
            local description = self.help.description
            logger:write("")
            for _, line in ipairs(
                print_aligned(description, opts.depth + 2)
            ) do
                logger:write(line)
            end
            local arguments   = self.help.arguments
            logger:write("")
            if arguments then
                for _, arg in ipairs(arguments) do
                    logger:write('%s%s', string.rep(' ', opts.depth + 2), arg[1])
                    for _, line in ipairs(
                        print_aligned(arg[2], opts.depth + 4)
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
}

local function tctl_method_new(name, callback, opts)
    -- checks must be here
    local help = opts.help
    opts.help = nil
    return setmetatable({
        name     = name,
        callback = callback,
        opts     = opts,
        help     = help
    }, {
        __index = tctl_method_methods
    })
end

local tctl_library_plugin_methods = {
    register_method  = function(self, name, callback, opts)
        logger:debug("registering method '%s' for library '%s'",
                     name, self.name)
        opts = deepcopy(opts or {})
        opts.help = opts.help or {}
        assert(type(opts.help.header) == 'string' or
               type(opts.help.header) == 'table')
        assert(type(opts.help.description) == 'string')
        if not opts.help.weight then
            opts.help.weight = fun.iter(self.methods):map(function(_, val)
                return val.help.weight
            end):chain({ 0 }):max() + 10
        end
        if self.methods[name] ~= nil then
            logger:error_xc('Method "%s" exists in "%s" library',
                            name, self.name)
        end

        local meth_instance = tctl_method_new(name, callback, opts)
        self.methods[name] = meth_instance

        return meth_instance:plugin_api()
    end,
    register_prepare = function(self, name, callback)
        logger:debug("registering context prepare function '%s'", name)
        if not is_callable(callback) then
            logger:error_xc('prepare function "%s" is not callable', name)
        end
        table.insert(self.prepare, {name, callback})
    end
}

local tctl_library_methods = {
    plugin_api = function(self)
        return setmetatable(fun.iter(self):tomap(), {
            __index = tctl_library_plugin_methods,
        })
    end,
    public_api = function(self)
        return self
    end,
    return_sorted = function(self)
        local sorted = fun.iter(self.methods):map(function(name, val)
            return {val.help.weight or 0, name}
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
                if method.help.linkmode then
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
                                string.rep(' ', opts.depth), self.name)
            else
                logger:error("Expected command name, got nothing")
            end
        elseif self.methods[self.command] == nil then
            logger:error("Command '%s' isn't found in module '%s'",
                         self.command, self.name)
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
            self.context.command_name = self.command
            self.context.positional_arguments = {}
            self.context.keyword_arguments    = {}
            for k, v in pairs(tarantoolctl.arguments) do
                if type(k) == 'number' then
                    self.context.positional_arguments[k] = v
                else
                    self.context.keyword_arguments[k] = v
                end
            end
            for _, prepare in ipairs(self.prepare) do
                local name, cb = unpack(prepare)
                logger:debug("running context prepare function '%s'", name)
                if cb(tarantoolctl:public_api(), self.context) == false then
                    return self:usage()
                end
            end
        end
        return wrapper:run(self.context)
    end,
}

local function tctl_library_new(name, opts)
    local help = opts.help
    opts.help = nil
    return setmetatable({
        name        = name,
        command     = nil,
        methods     = {},
        prepare     = {},
        context     = {},
        arguments   = tarantoolctl.arguments,
        opts        = opts,
        help        = help
    }, {
        __index = tctl_library_methods,
    })
end

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

local tctl_plugin_methods = {
    register_library = function(self, name, opts)
        logger:debug("registering library '%s'", name)
        opts = deepcopy(opts or {})
        opts.help = opts.help or {}
        if self.libraries[name] ~= nil then
            logger:error("failed to register library. already exists")
            return nil
        end
        if not opts.help.weight then
            opts.help.weight = fun.iter(self.libraries):map(function(_, val)
                return val.help.weight
            end):chain({ 0 }):max() + 10
        end

        local lib_instance = tctl_library_new(name, opts)
        self.libraries[name] = lib_instance

        return lib_instance:plugin_api()
    end,
    register_alias   = function(self, name, dotted_path, cfg)
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
    end,
    register_config  = function(self, name, tp, default)
        logger:debug("registering configuration value '%s'", name)
        logger:debug("type '%s'. defaults to '%s'", tp, default)
        self.cfg:register(name, tp, default)
    end
}

local tctl_public_methods = {
    get_config = function(self, name)
        logger:debug("getting configuration value for '%s'", name)
        return self.cfg:get(name)
    end
}

local tctl_methods = {
    load_defaults = function(self)
        self.usermode, self.defaults = find_defaults_file()
        self.cfg:load(self.defaults)
    end,
    load_plugins = function(self)
        package.loaded['ctl'] = self:plugin_api()
        self:load_plugin_embedded()
        self:load_plugin_directory(DEFAULT_PLUGIN_PATH)
        local plugin_path = self.cfg:get('plugin_path')
        if plugin_path ~= nil then
            self:load_plugin_directory(plugin_path)
        end
        package.loaded['ctl'] = nil
    end,
    load_plugin_embedded = function(self)
        load_func_sandboxed(plugin_ctl,  {},  'ctl plugin')
        load_func_sandboxed(plugin_xlog, {}, 'xlog plugin')
    end,
    load_plugin_directory = function(self, plugin_dir_path)
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

        for n, file in ipairs(plugins) do
            file = fio.abspath(file)
            logger:debug("loading plugin %s '%s'",
                            plugin_count_len(n, plugin_cnt),
                            file)
            load_file_sandboxed(file, {}, 'plugins')
        end
    end,
    plugin_api = function(self)
        return setmetatable(fun.iter(self):tomap(), {
            __index = tctl_plugin_methods,
        })
    end,
    public_api = function(self)
        return setmetatable(fun.iter(self):tomap(), {
            __index = tctl_public_methods,
        })
    end,
    usage = function(self, opts)
        opts = opts or {}
        opts.detailed = opts.detailed or false
        opts.depth    = opts.depth    or 0
        opts.header   = opts.header   or false

        if self.command ~= nil then
            logger:error("Unknown library or command name '%s'", self.command)
            logger:error("")
        end

        usage_header()

        local sorted = fun.iter(self.libraries):map(function(name, val)
            return {val.help.weight or 0, name}
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

tarantoolctl = setmetatable({
    libraries = {},
    aliases   = {},
    plugins   = {},
    cfg = tarantoolctl_cfg_new(),
}, {
    __index = tctl_methods
})
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

    tctl.cfg:register('plugin_path', 'string', yaml.NULL)

    tctl:load_defaults()
    tctl:load_plugins()

    tarantoolctl:run()
end

if is_main() then
    execute_wrapped(runner, tarantoolctl, arg)
else
    -- return table for testing
    return {}
end
