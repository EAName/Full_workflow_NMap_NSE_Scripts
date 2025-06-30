-- custom_scripts/enhanced-discovery.nse
-- Enhanced network discovery with service correlation
-- Author: Your Name
-- License: Same as Nmap

local nmap = require "nmap"
local stdnse = require "stdnse"
local ipOps = require "ipOps"

portrule = function(host, port)
  return port.number == 80 or port.number == 443 or port.number == 22 or port.number == 3389
end

action = function(host, port)
  local result = {}
  result["ip"] = host.ip
  result["port"] = port.number
  result["service"] = port.service or "unknown"
  result["state"] = port.state
  result["hostname"] = host.name or ""
  result["os"] = host.os and host.os.osmatch and host.os.osmatch[1] and host.os.osmatch[1].name or "unknown"
  return stdnse.format_output(true, result)
end 