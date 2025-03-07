--[[

LuCI Snort module

Copyright (C) 2015, Itus Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Author: Luka Perkov <luka@openwrt.org>

Version 4:
Redo some of the system calls and file paths for the updated Firmware

version 3
Modified by Roadrunnere42 added if then statement to choose which mode the shield's in and display in >>services >> intrusion prevention window
either one snort config file or 2 snort config files if running in router mode.

version 2
Modified by Roadrunnere42 to include a tab called priority 1 logs in intrusion prevention window, which displays any IPS rules that has trigger a priority 1 log in the IPS log.
/usr/lib/lua/luci/model/cbi/snort.lua - changed
/tmp/snort/priority1 - added to hold priority 1 logs

version 1
Modified by Roadrunnere42 to include a tab called rule counter in intrusion prevention window, which displays the number of rules that each rule set has.
This requires the following files to be changed or added
/tmp/rule_counter.log                 - created when run
/sbin/fw_upgrade.sh                   - changed
/usr/lib/lua/luci/model/cbi/snort.lua - changed

]]--

local fs = require "nixio.fs"
local sys = require "luci.sys"
require "ubus"

m = Map("snort", translate("Intrusion Prevention"), translate("<p>Changes may take a couple of minutes to take effect, service may be interrupted during that time.  Where you have edited rules, the system will need to download and re-process the new rulesets and any exclusions specified.</p><p>The IPS engine will restart each time you click the Save & Apply or On/Off button.</p><p><b>DO NOT REFRESH</b> if you see a <b>Bad Gateway</b> timeout message presented, since that may re-process your changes again.  Instead, place the cursor in your address bar and press Enter to re-navigate back to this page.</p>"))

m.on_init = function()
--[[
   -- Get the Shield Mode
   io.input("/var/.mode")
   line = io.read("*line")
   if line == "Router" then
   luci.sys.call("cp /var/log/snort/alert.fast /var/log/snort/alert.log")
   luci.sys.call("sed '1!G;h$!d' /var/log/snort/alert.log > /var/log/snort/snort_luci.log")
   luci.sys.call("rm /var/log/snort/alert.log")
   end
   luci.sys.call("grep -i 'priority: 1' /var/log/snort/snort_luci.log > /var/log/snort/priority1.log")
--]]
end

m.reset = false
m.submit = false

s = m:section(NamedSection, "snort")
s.anonymous = true
s.addremove = false

s:tab("tab_basic", translate("Basic Settings"))
s:tab("tab_advanced", translate("Advanced Settings"))
s:tab("tab_engine", translate("Engine"))
s:tab("tab_preprocessors", translate("Preprocessors"))
s:tab("tab_threshold", translate("Threshold Config"))
s:tab("tab_other", translate("Other Settings"))
s:tab("tab_rule_selector", translate("Rule Selector"))
s:tab("tab_rules", translate("Exclude Rules"))
s:tab("tab_custom", translate("Custom Rules"))
s:tab("tab_counter", translate("Rule Counter"))
s:tab("tab_logs", translate("IPS Logs"))
s:tab("tab_priority", translate("IPS Priority 1 Log"))
--s:tab("tab_snort1", translate("Snort Rules Selector"))

--------------------- Basic Tab ------------------------
local status="not running"
require "ubus"
local conn = ubus.connect()
if not conn then
	error("Failed to connect to ubusd")
end

for k, v in pairs(conn:call("service", "list", { name="snort" })) do
	status="running"
end

button_start = s:taboption("tab_basic",Button, "start", translate("Status: "))
if status == "running" then
	button_start.inputtitle = "ON"
else
	button_start.inputtitle = "OFF"
end

button_start.write = function(self, section)
						if status == "not running" then
							sys.call("service snort start")
							button_start.inputtitle = "ON"
							button_start.title = "Status: "
						else
							sys.call("service snort stop")
							button_start.inputtitle = "OFF"
							button_start.title = "Status: "
						end
					 end

if status == "running" then
	button_restart = s:taboption("tab_basic", Button, "restart", translate("Restart: "))
	button_restart.inputtitle = "Restart"
	button_restart.write = function(self, section)
								sys.call("service snort restart")   
						   end
end

--[[  io.input("/var/.mode")
  line = io.read("*line")
  if line == "Router" then
   --------------------- Snort Instance WAN Tab -----------------------

   config_file1 = s:taboption("tab_wan", TextValue, "text1", "")
   config_file1.wrap = "off"
   config_file1.rows = 25
   config_file1.rmempty = false

   function config_file1.cfgvalue()
      local uci = require "luci.model.uci".cursor_state()
      file = "/etc/snort/snort7.conf"
      if file then
         return fs.readfile(file) or ""
      else
         return ""
      end
   end

   function config_file1.write(self, section, value)
      if value then
         local uci = require "luci.model.uci".cursor_state()
	       file = "/etc/snort/snort7.conf"
	       fs.writefile(file, value:gsub("\r\n", "\n"))
	       luci.sys.call("/etc/init.d/snort restart")
      end
   end
   ---------------------- Snort Instance LAN Tab ------------------------

   config_file2 = s:taboption("tab_lan", TextValue, "text2", "")
   config_file2.wrap = "off"
   config_file2.rows = 25
   config_file2.rmempty = false

   function config_file2.cfgvalue()
      local uci = require "luci.model.uci".cursor_state()
      file = "/etc/snort/snort8.conf"
      if file then
         return fs.readfile(file) or ""
      else
         return ""
      end
   end

   function config_file2.write(self, section, value)
      if value then
         local uci = require "luci.model.uci".cursor_state()
	 file = "/etc/snort/snort8.conf"
	 fs.writefile(file, value:gsub("\r\n", "\n"))
	 luci.sys.call("/etc/init.d/snort restart")
      end
   end

   else
   ---------------------- Snort Config Tab ------------------------

   config_file2 = s:taboption("tab_config", TextValue, "config1", "")
   config_file2.wrap = "off"
   config_file2.rows = 25
   config_file2.rmempty = false

   function config_file2.cfgvalue()
      local uci = require "luci.model.uci".cursor_state()
      file = "/etc/snort/snort_bridge.conf"
      if file then
         return fs.readfile(file) or ""
      else
	       return ""
      end
   end

   function config_file2.write(self, section, value)
      if value then
         local uci = require "luci.model.uci".cursor_state()
         file = "/etc/snort/snort_bridge.conf"
         fs.writefile(file, value:gsub("\r\n", "\n"))
         luci.sys.call("/etc/init.d/snort restart")
      end
   end
end
--]]

--------------------- Advanced Tab -----------------------
config_file1 = s:taboption("tab_advanced", TextValue, "text1", "")
config_file1.wrap = "off"
config_file1.rows = 25
config_file1.rmempty = false

function config_file1.cfgvalue()
	local uci = require "luci.model.uci".cursor_state()
	file = "/etc/snort/profile/config1_advanced.conf"
	if file then
		return fs.readfile(file) or ""
	else
		return ""
	end
end

function config_file1.write(self, section, value)
	if value then
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/profile/config1_advanced.conf"
		fs.writefile(file, value:gsub("\r\n", "\n"))
		luci.sys.call("/etc/init.d/snort restart")
--      luci.sys.call("/etc/init.d/suricata restart")
	end
end


---------------------- Engine Tab ------------------------
config_file2 = s:taboption("tab_engine", TextValue, "text2", "")
config_file2.wrap = "off"
config_file2.rows = 25
config_file2.rmempty = false

function config_file2.cfgvalue()
	local uci = require "luci.model.uci".cursor_state()
	file = "/etc/snort/profile/config2_engine.conf"
	if file then
		return fs.readfile(file) or ""
	else
		return ""
	end
end

function config_file2.write(self, section, value)
	if value then
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/profile/config2_engine.conf"
		fs.writefile(file, value:gsub("\r\n", "\n"))
		luci.sys.call("/etc/init.d/snort restart")
--      luci.sys.call("/etc/init.d/suricata restart")
	end
end

------------------- Preprocessors Tab ---------------------
config_file3 = s:taboption("tab_preprocessors", TextValue, "text3", "")
config_file3.wrap = "off"
config_file3.rows = 25
config_file3.rmempty = false

function config_file3.cfgvalue()
	local uci = require "luci.model.uci".cursor_state()
	file = "/etc/snort/profile/config3_preprocessors.conf"
	if file then
		return fs.readfile(file) or ""
	else
		return ""
	end
end

function config_file3.write(self, section, value)
	if value then
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/profile/config3_preprocessors.conf"
		fs.writefile(file, value:gsub("\r\n", "\n"))
		luci.sys.call("/etc/init.d/snort restart")
--      luci.sys.call("/etc/init.d/suricata restart")
	end
end

---------------------- Threshold Config Tab ------------------------
threshold_config = s:taboption("tab_threshold", TextValue, "threshold", "")
threshold_config.wrap = "off"
threshold_config.rows = 25
threshold_config.rmempty = false

function threshold_config.cfgvalue()
	local uci = require "luci.model.uci".cursor_state()
	file = "/etc/snort/threshold.conf"
	if file then
		return fs.readfile(file) or ""
	else
		return ""
	end
end

function threshold_config.write(self, section, value)
	if value then
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/threshold.conf"
		fs.writefile(file, value:gsub("\r\n", "\n"))
		luci.sys.call("/etc/init.d/snort restart")
	end
end

--------------------- Other Tab ------------------------
other_config = s:taboption("tab_other", TextValue, "text4", "")
other_config.wrap = "off"
other_config.rows = 25
other_config.rmempty = false

function other_config.cfgvalue()
	local uci = require "luci.model.uci".cursor_state()
	file = "/etc/snort/profile/config4_other.conf"
	if file then
		return fs.readfile(file) or ""
	else
		return ""
	end
end

function other_config.write(self, section, value)
	if value then
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/profile/config4_other.conf"
		fs.writefile(file, value:gsub("\r\n", "\n"))
		luci.sys.call("/etc/init.d/snort restart")
--      luci.sys.call("/etc/init.d/suricata restart")
	end
end

--------------------- Snort Rule Selector Tab ------------------------
community_rules = s:taboption("tab_rule_selector", Flag, "community_rules", translate("Community rules"), translate(""))
community_rules.default=community_rules.enabled
community_rules.rmempty = false

function community_rules.cfgvalue(self, section)
	local val = m.uci:get_bool("snort", "rules", "community")
	if val == "false" then
		return false
	else
		return true
	end
end

function community_rules.write(self, section, value)
	if value then
		m.uci:delete("snort", "rules", "community")
	else
		m.uci:set("snort", "rules", "community", "false")
	end
end

sslbl_rules = s:taboption("tab_rule_selector", ListValue, "sslbl_rules", translate("SSL Blacklist"), translate("Bad SSL certificates identified by abuse.ch to be associated with malware or botnet activities.  Default settings will block certificates identified in the past 30 days. Aggressive will block <b>all</b> identified certificates with potential for false positives."))
sslbl_rules.default = ""
sslbl_rules:value("off", translate("Off"))
sslbl_rules:value("", translate("Default"))
sslbl_rules:value("aggressive", translate("Aggressive"))

function sslbl_rules.cfgvalue(...)
	return m.uci:get("snort", "rules", "sslbl")
end

function sslbl_rules.write(self, section, value)
	if value == "" then
		m.uci:delete("snort", "rules", "sslbl")
	else	
		m.uci:set("snort", "rules", "sslbl", value)
	end
end

emerging_rules = s:taboption("tab_rule_selector", TextValue, "emergingThreats", translate("Uncomment rules from <a href='https://doc.emergingthreats.net/bin/view/Main/EmergingFAQ' target='_blank'>Emerging Threats</a> that you want included as DROPs within your snort.rules"))
emerging_rules.wrap = "off"
emerging_rules.rows = 25
emerging_rules.rmempty = false

function emerging_rules.cfgvalue()
	local uci = require "luci.model.uci".cursor_state()
	file = "/etc/snort/rules/emerging-threats.rules"
	if file then
		return fs.readfile(file) or ""
	else
		return ""
	end
end

function emerging_rules.write(self, section, value)
	if value then
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/rules/emerging-threats.rules"
		fs.writefile(file, value:gsub("\r\n", "\n"))
		luci.sys.call("/etc/snort/updaterules.sh")
	end
end

--------------------- Exclude Rules Tab ------------------------
exclude_rules = s:taboption("tab_rules", TextValue, "excludeRules", translate("<p>Some rules can cause issues with certain apps or websites</p><p>You can exclude these rules if you identify their <abbr title=\"Snort Intrusion Detection\">sid</abbr> numbers</p><p><a href='https://snort.org/documents#OfficialDocumentation' target='_blank'>Read more</a></p>"))
exclude_rules.wrap = "off"
exclude_rules.rows = 25
exclude_rules.rmempty = false

function exclude_rules.cfgvalue()
	local uci = require "luci.model.uci".cursor_state()
	file = "/etc/snort/rules/exclude.rules"
	if file then
		return fs.readfile(file) or ""
	else
		return ""
	end
end

function exclude_rules.write(self, section, value)
	if value then
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/rules/exclude.rules"
		fs.writefile(file, value:gsub("\r\n", "\n"))
		luci.sys.call("/etc/snort/updaterules.sh")
	end
end

---------------------- Custom Rules Tab ------------------------
custom_rules = s:taboption("tab_custom", TextValue, "customRules", "")
custom_rules.wrap = "off"
custom_rules.rows = 25
custom_rules.rmempty = false

function custom_rules.cfgvalue()
	local uci = require "luci.model.uci".cursor_state()
	file = "/etc/snort/rules/local.rules"
	if file then
		return fs.readfile(file) or ""
	else
		return ""
	end
end

function custom_rules.write(self, section, value)
	if value then
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/rules/local.rules"
		fs.writefile(file, value:gsub("\r\n", "\n"))
		luci.sys.call("/etc/init.d/snort restart")
	end
end

--------------------- Rule Counter Tab ------------------------
counter = s:taboption("tab_counter", TextValue, "Counter", "")
counter.wrap = "off"
counter.rows = 25
counter.rmempty = false

function counter.cfgvalue()
	local uci = require "luci.model.uci".cursor_state()
	local file = "/var/log/snort/rule_counter.log"
	if file then
		return fs.readfile(file) or ""
	else
		return ""
	end
end

--------------------- Logs Tab ------------------------
snort_logfile = s:taboption("tab_logs", TextValue, "logfile", "")
snort_logfile.wrap = "off"
snort_logfile.rows = 25
snort_logfile.rmempty = false

function snort_logfile.cfgvalue()
	local uci = require "luci.model.uci".cursor_state()
	local file = "/var/log/snort/snort_luci.log"
	if file then
		return fs.readfile(file) or ""
	else
		return ""
	end
end

---------------------Priority Tab ------------------------
snort_logfile1 = s:taboption("tab_priority", TextValue, "IPS Priority 1 Log", "")
snort_logfile1.wrap = "off"
snort_logfile1.rows = 25
snort_logfile1.rmempty = false

function snort_logfile1.cfgvalue()
	local uci = require "luci.model.uci".cursor_state()
	local file = "/etc/snort/logs/priority1.log"
	if file then
		return fs.readfile(file) or ""
	else
		return ""
	end
end

return m
