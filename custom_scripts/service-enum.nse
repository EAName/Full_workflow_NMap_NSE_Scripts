-- custom_scripts/service-enum.nse
-- Comprehensive service enumeration
-- Author: Your Name
-- License: Same as Nmap

local nmap = require "nmap"
local stdnse = require "stdnse"

portrule = function(host, port)
  return port.state == "open"
end

action = function(host, port)
  local service = port.service or "unknown"
  local version = port.version or "unknown"
  local banner = port.banner or ""
  return string.format("Service: %s | Version: %s | Banner: %s", service, version, banner)
end 