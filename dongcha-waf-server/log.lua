local _M = {}
local logger = require "resty.openwaf.socket"
local cjson = require "cjson.safe"
local waf = require "resty.openwaf.waf"
local config_info = waf.get_config_info()
_M.version = "1.0"


-- 开启syslog远程日志记录
if config_info.log_remote == "true" then
	if not logger.initted() then
		local ok,err = logger.init{
				host = config_info.log_ip,
				port = tonumber(config_info.log_port),
				sock_type = config_info.log_sock_type,
				flush_limit = tonumber(config_info.log_flush_limit),
				}
		if not ok then
			ngx.log(ngx.ERR,"failed to initialize the logger: ",err)
			return
		end
	end
	--[[ CC 速率检测拦截
	if rule_limit_reject_log then
		rule_limit_reject_log['http_request_time'] = ngx.localtime()
		rule_limit_reject_log['http_request_host'] = ngx.req.get_headers()["Host"]
		local bytes, err = logger.log(cjson.encode(rule_limit_reject_log))
		if err then
			ngx.log(ngx.ERR, "failed to log message: ", err)
		end
	end

	-- CC 单位时间总量拦截
	if rule_limit_delay_log then
		rule_limit_delay_log['http_request_time'] = ngx.localtime()
		rule_limit_delay_log['http_request_host'] = ngx.req.get_headers()["Host"]
		local bytes, err = logger.log(cjson.encode(rule_limit_delay_log))
		if err then
			ngx.log(ngx.ERR, "failed to log message: ", err)
		end
	end
	]]
	-- 非观察模式日志记录
	if config_info.observ_mode ~= "true" then
		local rule_log = ngx.ctx.rule_log
		local geo_rule_log = ngx.ctx.geo_rule_log
		local rule_limit_reject_log = ngx.ctx.rule_limit_reject_log
		local rule_limit_delay_log = ngx.ctx.rule_limit_delay_log
		if rule_log then
			rule_log['request_status'] = "拦截"
			rule_log['http_request_time'] = ngx.localtime()
			rule_log['http_request_host'] = ngx.req.get_headers()["Host"]
			local match_captures = rule_log['rule_match_captures']
			if match_captures then
				rule_log['rule_match_captures'] = ngx.re.gsub(match_captures, [=[\\x]=], [=[\\x]=], "oij")
				rule_log['rule_match_captures'] = ngx.re.gsub(match_captures, [=[\\u]=], [=[\\u]=], "oij")
			end
			local bytes, err = logger.log(cjson.encode(rule_log))
			if err then
				ngx.log(ngx.ERR, "failed to log message: ", err)
			end
		elseif rule_limit_reject_log then
			rule_limit_reject_log['http_request_time'] = ngx.localtime()
			rule_limit_reject_log['http_request_host'] = ngx.req.get_headers()["Host"]
			local bytes, err = logger.log(cjson.encode(rule_limit_reject_log))
			if err then
				ngx.log(ngx.ERR, "failed to log message: ", err)
			end
		elseif rule_limit_delay_log then
			rule_limit_delay_log['http_request_time'] = ngx.localtime()
			rule_limit_delay_log['http_request_host'] = ngx.req.get_headers()["Host"]
			local bytes, err = logger.log(cjson.encode(rule_limit_delay_log))
			if err then
				ngx.log(ngx.ERR, "failed to log message: ", err)
			end
		elseif geo_rule_log then
			geo_rule_log['http_request_time'] = ngx.localtime()
			geo_rule_log['http_request_host'] = ngx.req.get_headers()["Host"]
			local bytes, err = logger.log(cjson.encode(geo_rule_log))
			if err then
				ngx.log(ngx.ERR, "failed to log message: ", err)
			end
		end
	else
		-- 观察模式日志
		local rule_observ_log = ngx.ctx.rule_observ_log
		if rule_observ_log and #rule_observ_log ~= 0 then
			for  _,v in ipairs(rule_observ_log) do
				v['request_status'] = "放行"
				v['http_request_time'] = ngx.localtime()
				v['http_request_host'] = ngx.req.get_headers()["Host"]
				local match_captures = v['rule_match_captures']
				if match_captures then
					v['rule_match_captures'] = ngx.re.gsub(match_captures, [=[\\x]=], [=[\\x]=], "oij")
					v['rule_match_captures'] = ngx.re.gsub(match_captures, [=[\\u]=], [=[\\u]=], "oij")
				end
				local bytes, err = logger.log(cjson.encode(v))
				if err then
					ngx.log(ngx.ERR, "failed to log message: ", err)
				end
			end
		end
	end
end


-- 本地日志记录
if config_info.log_local == "true" then
	if config_info.observ_mode ~= "true" then
		-- 非观察模式日志
		local rule_log = ngx.ctx.rule_log
		local geo_rule_log = ngx.ctx.geo_rule_log
		local rule_limit_reject_log = ngx.ctx.rule_limit_reject_log
		local rule_limit_delay_log = ngx.ctx.rule_limit_delay_log
		if rule_log then
			rule_log['request_status'] = "拦截"
			rule_log['http_request_time'] = ngx.localtime()
			rule_log['http_request_host'] = ngx.req.get_headers()["Host"]
			local match_captures = rule_log['rule_match_captures']
			if match_captures then
				rule_log['rule_match_captures'] = ngx.re.gsub(match_captures, [=[\\x]=], [=[\\x]=], "oij")
				rule_log['rule_match_captures'] = ngx.re.gsub(match_captures, [=[\\u]=], [=[\\u]=], "oij")
			end
			ngx.log(ngx.ERR,cjson.encode(rule_log))
		elseif rule_limit_reject_log then
			rule_limit_reject_log['http_request_time'] = ngx.localtime()
			rule_limit_reject_log['http_request_host'] = ngx.req.get_headers()["Host"]
			ngx.log(ngx.ERR,cjson.encode(rule_limit_reject_log))

		elseif rule_limit_delay_log then
			rule_limit_delay_log['http_request_time'] = ngx.localtime()
			rule_limit_delay_log['http_request_host'] = ngx.req.get_headers()["Host"]
			ngx.log(ngx.ERR,cjson.encode(rule_limit_delay_log))
		elseif geo_rule_log then
			geo_rule_log['http_request_time'] = ngx.localtime()
			geo_rule_log['http_request_host'] = ngx.req.get_headers()["Host"]
			ngx.log(ngx.ERR,cjson.encode(geo_rule_log))
		end

	else
		-- 观察模式日志
		local rule_observ_log = ngx.ctx.rule_observ_log
		if rule_observ_log and type(rule_observ_log) ~= "table" then
			ngx.log(ngx.ERR,"BUG find!!!")
			ngx.log(ngx.ERR,ngx.req.raw_header())
			ngx.log(ngx.ERR,ngx.req.get_body_data())
		end
		if rule_observ_log and #rule_observ_log ~= 0 then
			for  _,v in ipairs(rule_observ_log) do
				v['request_status'] = "放行"
				v['http_request_time'] = ngx.localtime()
				v['http_request_host'] = ngx.req.get_headers()["Host"]
				local match_captures = v['rule_match_captures']
				if match_captures then
					v['rule_match_captures'] = ngx.re.gsub(match_captures, [=[\\x]=], [=[\\x]=], "oij")
					v['rule_match_captures'] = ngx.re.gsub(match_captures, [=[\\u]=], [=[\\u]=], "oij")
				end
				ngx.log(ngx.ERR,cjson.encode(v))
			end
		end
	end
end
