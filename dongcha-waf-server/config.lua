--[[
Author: Daboluo
Date: 2019-09-17 19:48:31
LastEditTime: 2020-08-24 23:29:26
LastEditors: Do not edit
--]]
local _M = {
    version = "1.0",
    config_path = "/data/semf/config/openresty/openwaf/conf/openwaf_config.json",
    local_global_path = "/data/semf/config/openresty/openwaf/conf/openwaf_local_global.json",
    local_base_config_path = "/data/semf/config/openresty/openwaf/conf/openwaf_local_base_config.json",
    local_base_config_null_path = "/data/semf/config/openresty/openwaf/conf/openwaf_local_base_null_config.json",
    libmaxminddb_path = "/data/semf/openresty/lualib/libmaxminddb.so",
    config_geo_path = "/data/semf/config/openresty/openwaf/conf/GeoLite2-Country.mmdb"
}

return _M
