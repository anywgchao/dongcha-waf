local enc_ck = require "resty.openwaf.enc_ck"
local waf = require "resty.openwaf.waf"

local resp_header_chunk = waf.resp_header_chunk()
enc_ck.resp_aes_ck()
if resp_header_chunk  or ngx.ctx.resp_action then
    ngx.header.content_length = nil
end
