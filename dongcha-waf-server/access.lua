local waf = require "resty.openwaf.waf"

waf.access_init()
waf.geo_protection()
waf.limitreq_check()
waf.base_check()
