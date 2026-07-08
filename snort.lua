HOME_NET = 'any'
EXTERNAL_NET = 'any'

include 'snort_defaults.lua'

http_inspect = { }
-- Valid Snort 3 port_scan configuration to prevent OOM and detect scans
port_scan = default_med_port_scan
port_scan.tcp_window = 15
port_scan.udp_window = 15
port_scan.icmp_window = 15
-- memcap is implicitly 10MB (10485760 bytes) in Snort 3, which inherently prevents OOM.

-- Static Port Binding explicitly avoids the 'wizard' module which crashes Snort 3.12.2.0 on shutdown
binder = {
    { when = { proto = 'tcp', ports = '80' }, use = { type = 'http_inspect' } }
}

ips = {
    variables = default_variables,
    enable_builtin_rules = true,
    mode = "tap",
    include = "/mnt/extra_storage/IDS_Project/snort3-community-rules/snort3-community.rules"
}

-- Suppress specific noisy or unwanted built-in rules
suppress = {
    { gid = 116, sid = 444 }, { gid = 1, sid = 1917 }, { gid = 116, sid = 414 },
    { gid = 116, sid = 408 }, { gid = 1, sid = 254 }, { gid = 122, sid = 3 },
    { gid = 116, sid = 58 }, { gid = 1, sid = 402}, { gid = 1, sid = 1444}, 
    { gid = 1, sid = 403} 
  
-- GID 1   : Text rule alerts
-- GID 116 : IP/ARP events
-- GID 119 : HTTP inspection
-- GID 129 : TCP stream events
-- GID 137 : SSL/TLS inspection
}