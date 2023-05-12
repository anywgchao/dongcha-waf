--[[
Author: Daboluo
Date: 2019-09-17 19:48:31
LastEditTime: 2020-08-24 23:29:26
LastEditors: Do not edit
--]]
require "resty.core"

local hashkey = require "resty.openwaf.hashkey"
local waf = require "resty.openwaf.waf"
local config = require "resty.openwaf.config"
local results = hashkey.license_check(config.config_path)

if results == true then
    waf.init(config.config_path)
end
