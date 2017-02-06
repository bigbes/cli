local log          = require('ctl.log')
local tarantoolctl = require('ctl')

log:debug('inside plugin')

local lib = tarantoolctl:register_library('custom')

local function tctl_cs_1(tctl)
    log:write('method inside')
end

lib:register_method('lustom', tctl_cs_1)
