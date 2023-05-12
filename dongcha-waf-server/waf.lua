local cjson = require "cjson.safe"
local init_config    = require "resty.openwaf.config"
local request = require "resty.openwaf.request"
local transform = require "resty.openwaf.transform"
local operator = require "resty.openwaf.operator"
local resty_random = require "resty.random"
local str = require "resty.string"
local pairs = pairs
local ipairs = ipairs
local table_insert = table.insert
local table_sort = table.sort
local table_concat = table.concat
local http = require "resty.openwaf.http"
local upload = require "resty.upload"
local limitreq = require "resty.openwaf.limitreq"
local geo = require 'resty.openwaf.maxminddb'
local _M = {}
_M.version = "1.0"


local _config_path = init_config.config_path
local _local_global_path = init_config.local_global_path
local _local_base_config_path = init_config.local_base_config_path
local _local_base_config_null_path = init_config.local_base_config_null_path
local _config_geo_path = init_config.config_geo_path

local _config_info = {}
local _rules = {}
local _resp_rules = {}
local _limit_req_rules = {}
local _resp_header_chunk = nil
local function _sort_rules(a,b)
	return tonumber(a.rule_id)<tonumber(b.rule_id)
end


local function _process_request(var,otp)
	--Ignore specific parameter processing
	local t = request.request[var.rule_var]()
	if type(t) ~= "string" and type(t) ~= "table" then
		ngx.log(ngx.ERR,"run fail,can not decode http args ",type(t).."   "..var.rule_var)
		ngx.log(ngx.ERR,ngx.req.raw_header())
		ngx.exit(500)
	end

	if type(t) == "string" then
		return t
	end

	local rule_var = var.rule_var
	if (rule_var == "ARGS" or rule_var == "ARGS_GET" or rule_var == "ARGS_POST" or rule_var == "REQUEST_COOKIES" or rule_var == "REQUEST_HEADERS" or rule_var == "RESP_HEADERS" ) then
		--指定参数处理
		if( type(var.rule_specific) == "table" ) then
			local specific_result = {}
			for _,v in ipairs(var.rule_specific) do
				local specific = t[v]
				if specific ~= nil then
					specific_result[v] = specific
				end
			end
			return specific_result
		end

		--忽略参数处理
		if( type(var.rule_ignore) == "table" ) then
			local ignore_result = {}
			ignore_result = t
			for _,v in ipairs(var.rule_ignore) do
				ignore_result[string.lower(v)] = nil
			end
			return ignore_result
		end
	end

	return t
end


function _M.process_request(var)
	return _process_request(var)
end


local function _process_transform(process_request,rule_transform,var)
	--Parameter processing conversion
	if type(process_request) ~= "string" and type(process_request) ~= "table" then
		ngx.log(ngx.ERR,"run fail,can not transfrom http args")
		exit_code.return_error()
	end

	if  type(rule_transform) ~= "table" then
		ngx.log(ngx.ERR,"run fail,can not decode config file,transfrom error")
		exit_code.return_error()
	end


	if type(process_request) == "string" then
		local string_result = process_request
		for _,v in ipairs(rule_transform) do
			string_result = transform.request[v](string_result)
		end
		return 	string_result
	end

	local result = {}
	local rule_var = var.rule_var
	if (rule_var == "ARGS" or rule_var == "ARGS_GET" or rule_var == "ARGS_POST" or rule_var == "REQUEST_COOKIES" or rule_var == "REQUEST_HEADERS" or rule_var == "RESP_HEADERS") then
		for k,v in pairs(process_request) do
			if type(v) == "table" then
				local _result_table = {}
				for _,_v in ipairs(v) do
					local _result = _v
					for _,__v in ipairs(rule_transform) do
						_result = transform.request[__v](_result)
					end
					if type(_result) == "string" then
						table_insert(_result_table,_result)
					end
				end
				result[k] = _result_table
			else
				local _result = v
				for _,_v in ipairs(rule_transform) do
					_result = transform.request[_v](_result)
				end
				if type(_result) == "string" then
					result[k] = _result
				end
			end
		end
	else
		for _,v in ipairs(process_request) do
			local _result = v
			for _,_v in ipairs(rule_transform) do
				_result = transform.request[_v](_result)
			end
			if type(_result) == "string" then
				table_insert(result,_result)
			end
		end
	end
	return result
end


local function _process_operator( process_transform , match , var , rule )
	--匹配操作过程
	local rule_operator = match.rule_operator
	local rule_pattern = match.rule_pattern
	local rule_negated = match.rule_negated
	local rule_var = var.rule_var
	if type(process_transform) ~= "string" and type(process_transform) ~= "table" then
		ngx.log(ngx.ERR,"run fail,can not operator http args")
		ngx.exit(500)
	end
	if type(rule_operator) ~= "string" and type(rule_pattern) ~= "string" then
		ngx.log(ngx.ERR,"rule_operator and rule_pattern error")
		ngx.exit(500)
	end

	if type(process_transform) == "string" then
		local result ,value,captures
		--规则匹配处理
		result,value,captures = operator.request[rule_operator](process_transform,rule_pattern)
		if rule_negated == "true" then
			result = not result
		end

		if result  then
			return result,value,rule_var,captures
		else
			return result
		end
	end

	if (rule_var == "ARGS" or rule_var == "ARGS_GET" or rule_var == "ARGS_POST" or rule_var == "REQUEST_COOKIES" or rule_var == "REQUEST_HEADERS" or rule_var == "RESP_HEADERS") then
		for k,v in pairs(process_transform) do
			if type(v) == "table" then
				for _,_v in ipairs(v) do
					local result,value,captures
					result,value,captures = operator.request[rule_operator](_v,rule_pattern)
					if rule_negated == "true" then
						result = not result
					end
					if result  then
						return result,value,k,captures
					end
				end
			else
				local result,value,captures
				result,value,captures = operator.request[rule_operator](v,rule_pattern)
				if rule_negated == "true" then
					result = not result
				end

				if result  then
					return result,value,k,captures
				end
			end
		end
	else
		for _,v in ipairs(process_transform) do
			local result,value,captures
			result,value,captures = operator.request[rule_operator](v,rule_pattern)
			if rule_negated == "true" then
				result = not result
			end

			if result  then
				return result,value,rule_var,captures
			end
		end
	end
	return false
end


local function _rule_match(rules)
	-- 规则匹配处理核心阶段
	local result
	local rule_observ_log = {}
	for _,rule in ipairs(rules) do
		--常规规则检测处理
		local matchs_result = true
		local ctx_rule_log = {}
		for _,match in ipairs(rule.rule_matchs) do
			local operator_result = false
			for _,var in ipairs(match.rule_vars) do
				local process_request = _process_request(var) 	--参数选择
				local process_transform = _process_transform(process_request,match.rule_transform,var) --参数处理
				local _operator_result,_operator_value,_operator_key,captures = _process_operator(process_transform,match,var,rule)
				if _operator_result and rule.rule_log == "true" then
					ctx_rule_log.rule_var = var.rule_var
					ctx_rule_log.rule_operator = match.rule_operator
					ctx_rule_log.rule_negated = match.rule_negated
					-- 参数转换处理
					ctx_rule_log.rule_transform = match.rule_transform
					if ngx.get_phase() == "body_filter" then
						ctx_rule_log.rule_match_var = var.rule_var
					else
						--匹配值
						ctx_rule_log.rule_match_var = _operator_value
					end
					-- 匹配到的关键词
					ctx_rule_log.rule_match_key = _operator_key
					ctx_rule_log.rule_uri = ngx.var.uri
					ctx_rule_log.remote_addr = ngx.var.remote_addr
					ctx_rule_log.rule_match_captures = captures
				end

				if  _operator_result then
					operator_result = _operator_result
					break
				end
			end

			if (not operator_result) then
				matchs_result = false
				break
			end
		end

		if matchs_result and rule.rule_log == "true" then
			ctx_rule_log.log_type = "owasp_log"
			ctx_rule_log.platform_tag = _config_info.waf_platform_tag
			ctx_rule_log.rule_id = rule.rule_id
			ctx_rule_log.rule_detail = rule.rule_detail
			ctx_rule_log.rule_serverity = rule.rule_serverity
			ctx_rule_log.rule_category = rule.rule_category
			ctx_rule_log.rule_action = rule.rule_action
			--如果"启用命中规则记录完整http请求"，则记录详细response信息
			if _config_info.log_all == "true" or rule.rule_log_all=="true" then
				ctx_rule_log.rule_headers =  request.request['REQUEST_HEADERS']()
				--ctx_rule_log.rule_url = request.request['REQUEST_URI']()
				ctx_rule_log.rule_raw_post =  ngx.req.get_body_data()
			end
			-- 如果不是CC限速规则，则记录日志
			--if rule.rule_action == "limit_req_rate" or rule.rule_action == "limit_req_count" then
			--else
			ngx.ctx.rule_log = ctx_rule_log
			--end
		end

		-- 如果是观察模式，监控日志开启，则合并table到ctx_rule_log
		if _config_info.observ_mode == "true" and matchs_result and rule.rule_log == "true" then
			table_insert(rule_observ_log,ctx_rule_log)
			matchs_result = false
		end

		if rule.rule_action == "pass" and matchs_result then
			matchs_result = false
		end

		-- 非全局CC处理引擎，针对某个IP后URI进行限速限流，如果观察模式matchs_result=false，则不执行
		--[[if _config_info.limitreq_engine == "true" and matchs_result and (rule.rule_action == "limit_req_rate" or rule.rule_action == "limit_req_count") then
			_limit_var(rule)
			matchs_result = false
		end]]

		if matchs_result then
			return matchs_result,rule
		end
	end

	ngx.ctx.rule_observ_log = rule_observ_log
	return result
end


function _M.rule_match(rules)
	return _rule_match(rules)
end

local function _global_local_update_rule()
	-- 如果使用本地配置文件，则初始化本地配置文件
	local init_local_config_path =  _local_global_path
	local read_local_config = assert(io.open(init_local_config_path,'r'))
	local raw_local_config_info = read_local_config:read('*all')
	read_local_config:close()
	local _update_rule = cjson.decode(raw_local_config_info)
	if _update_rule == nil then
		ngx.log(ngx.ERR,"init fail,can not decode local_global_rule")
	else
		_config_info.base_engine = _config_info.base_engine or _update_rule['base_engine'] or "true"
		_config_info.log_all = _config_info.log_all or  _update_rule['log_all'] or "false"
		_config_info.log_remote = _config_info.log_remote or  _update_rule['log_remote'] or "false"
		_config_info.log_local = _config_info.log_local or  _update_rule['log_local'] or "true"
		_config_info.http_redirect = _config_info.http_redirect or  _update_rule['http_redirect'] or "/"
		_config_info.log_ip = _config_info.log_ip or  _update_rule['log_ip'] or "127.0.0.1"
		_config_info.log_port = _config_info.log_port or  _update_rule['log_port'] or "5555"
		_config_info.log_sock_type = _config_info.log_sock_type or  _update_rule['log_sock_type'] or "udp"
		_config_info.log_flush_limit = _config_info.log_flush_limit or  _update_rule['log_flush_limit'] or "1"
		_config_info.cookie_safe = _config_info.cookie_safe or _update_rule['cookie_safe'] or "true"
		_config_info.cookie_safe_client_ip = _config_info.cookie_safe_client_ip or _update_rule['cookie_safe_client_ip'] or "true"
		_config_info.cookie_safe_is_safe = _config_info.cookie_safe_is_safe or _update_rule['cookie_safe_is_safe'] or "false"
		_config_info.aes_random_key = _config_info.aes_random_key or _update_rule['aes_random_key'] or  str.to_hex(resty_random.bytes(8))
		_config_info.observ_mode =  _config_info.observ_mode or _update_rule['observ_mode'] or "false"
		_config_info.resp_engine =  _config_info.resp_engine or _update_rule['resp_engine'] or "false"
		_config_info.limitreq_engine = _config_info.limitreq_engine or _update_rule['cc_engine'] or "false"
		_config_info.geo_protection = _config_info.geo_protection or _update_rule['geo_protection'] or "false"
		_config_info.template_status = _config_info.template_status or _update_rule['template_status'] or "false"
		_config_info.template_name = _config_info.template_name or _update_rule['template_name'] or "null"
		_config_info.template_type = _config_info.template_type or _update_rule['template_type'] or "null"
		_config_info.template_content = _config_info.template_content or _update_rule['template_content'] or "null"

		if _config_info.base_engine == "true" then
			ngx.log(ngx.ALERT,"success load global config base_engine: Open")
		else
			ngx.log(ngx.ALERT,"success load global config base_engine: Shutdown")
		end
		if _config_info.limitreq_engine == "true" then
			ngx.log(ngx.ALERT,"success load global config limitreq_engine: Open")
		else
			ngx.log(ngx.ALERT,"success load global config limitreq_engine: Shutdown")
		end

		if _config_info.geo_protection == "true" then
			if not geo.initted() then
				local res, err = geo.init(_config_geo_path)
				if err then
					ngx.log(ngx.ERR,err)
				end
				ngx.log(ngx.ALERT,"success load global config geo_engine: Open")
			end

			if not geo.initted() then
				ngx.log(ngx.ALERT,"success load global config geo_engine: Shutdown")
			end
		else
			ngx.log(ngx.ALERT,"success load global config geo_engine: Shutdown")
		end
	end
end


local function _local_base_update_rule(_local_base_config_path)
	--加载本地基础规则
	local _base_update_rule = {}
	local _resp_update_rule = {}
	local _limit_req_rule = {}
	local init_local_config_path =  _local_base_config_path
	local read_local_config = assert(io.open(init_local_config_path,'r'))
	local raw_local_config_info = read_local_config:read('*all')
	read_local_config:close()
	local _update_rule = cjson.decode(raw_local_config_info)
	if _update_rule == nil or #_update_rule == 0 then
		ngx.log(ngx.ERR,"init fail,can not decode base_rule_config_file")
	else
		for _,v in ipairs(_update_rule) do
			if v.rule_phase == "resp" then
				table_insert(_resp_update_rule,v)
				if v.rule_action == "inject_js" or v.rule_action == "rewrite" or v.rule_action == "replace" then
					_resp_header_chunk = true
				end
			else
				--if v.rule_action == "limit_req_rate" or v.rule_action == "limit_req_count" or v.rule_action == "limit_req_pass" then
				if _config_info.limitreq_engine == "true" and v.rule_phase == "cc" then
					--if _config_info.limitreq_engine == "true" then
						table_insert(_limit_req_rule,v)
					--end
				else
					table_insert(_base_update_rule,v)
				end
			end
		end

		table_sort(_resp_update_rule,_sort_rules)
		table_sort(_base_update_rule,_sort_rules)
		table_sort(_limit_req_rule,_sort_rules)
		_rules =  _base_update_rule
		_resp_rules = _resp_update_rule
		_limit_req_rules = _limit_req_rule
		ngx.log(ngx.ALERT,"success load base rule,count is: "..#_rules)
		ngx.log(ngx.ALERT,"success load resp rule,count is: "..#_resp_rules)
		ngx.log(ngx.ALERT,"success load limit_req rule,count is: "..#_limit_req_rules)
	end
end

local function _base_update_rule()
	local _base_update_rule = {}
	local _resp_update_rule = {}
	local _limit_req_rule = {}
	local _update_website = _config_info.base_rule_update_website or "http://192.144.135.9/waf/update_rule"
	local httpc = http.new()
	local body = {
		api_key = _config_info.waf_api_key or "openwaf",
		platform_tag = _config_info.waf_platform_tag or "openwaf",
	}
	local res, err = httpc:request_uri( _update_website , {
           method = "POST",
		   body = cjson.encode(body),
		   ssl_verify = false,
           headers = {
            ["Content-Type"] = "application/json",
           }
	})
	if not res then
		ngx.log(ngx.ERR,"failed to request: ", err)
		return
	end

	local read_body = res.body
	local _update_rule = cjson.decode(read_body)

	if _update_rule == nil then
		--线上基础规则加载失败，加载本地规则
		ngx.log(ngx.ALERT,"fail load remote_base_rule")
		if _config_info.base_engine == "true" or _config_info.resp_engine == "true" or _config_info.limitreq_engine == "true" then
			_local_base_update_rule(_local_base_config_path)
			ngx.log(ngx.ALERT,"success load local_base_rule_file")

			--线上基础规则加载失败,本地基础规则加载失败，加载本地空白规则
			if #_rules == 0 and #_resp_rules == 0 and #_limit_req_rules == 0  then
				ngx.log(ngx.ALERT,"fail load local_base_rule_file")
				_local_base_config_path = _local_base_config_null_path
				_local_base_update_rule(_local_base_config_path)
				ngx.log(ngx.ALERT,"success load local_base_rule_null_file")
			end
		end
	else
		for _,v in ipairs(_update_rule) do
			if v.rule_phase == "resp" then
				table_insert(_resp_update_rule,v)
				if v.rule_action == "inject_js" or v.rule_action == "rewrite" or v.rule_action == "replace" then
					_resp_header_chunk = true
				end
			else
				--if v.rule_action == "limit_req_rate" or v.rule_action == "limit_req_count" or v.rule_action == "limit_req_pass" then
				if _config_info.limitreq_engine == "true" and v.rule_phase == "cc" then
					--if _config_info.limitreq_engine == "true" then
						table_insert(_limit_req_rule,v)
					--end
				else
					table_insert(_base_update_rule,v)
				end
			end
		end

		table_sort(_resp_update_rule,_sort_rules)
		table_sort(_base_update_rule,_sort_rules)
		table_sort(_limit_req_rule,_sort_rules)
		_rules =  _base_update_rule
		_resp_rules = _resp_update_rule
		_limit_req_rules = _limit_req_rule
		ngx.log(ngx.ALERT,"success load remote_base_rule")
		ngx.log(ngx.ALERT,"success load base rule,count is: "..#_rules)
		ngx.log(ngx.ALERT,"success load resp rule,count is: "..#_resp_rules)
		ngx.log(ngx.ALERT,"success load limit_req rule,count is: "..#_limit_req_rules)
	end
end


local function _global_update_rule()
	-- 初始化更新线上全局变量
	local _update_website  =  _config_info.global_rule_update_website
	local httpc = http.new()
	local body = {
		api_key = _config_info.waf_api_key or "openwaf",
		platform_tag = _config_info.waf_platform_tag or "openwaf",
	}

	local res, err = httpc:request_uri( _update_website , {
	   method = "POST",
	   body = cjson.encode(body),
	   ssl_verify = false,
	   headers = {
		["Content-Type"] = "application/json"
	   }
	})
	if not res then
		ngx.log(ngx.ERR,"failed to request: ", err)
		return
	end

	local read_body = res.body
	local _update_rule = cjson.decode(read_body)

	if _update_rule ~= nil then
		_config_info.base_engine = _config_info.base_engine or _update_rule['base_engine'] or "true"
		_config_info.log_all = _config_info.log_all or  _update_rule['log_all'] or "false"
		_config_info.log_remote = _config_info.log_remote or  _update_rule['log_remote'] or "false"
		_config_info.log_local = _config_info.log_local or  _update_rule['log_local'] or "true"
		_config_info.http_redirect = _config_info.http_redirect or  _update_rule['http_redirect'] or "/"
		_config_info.log_ip = _config_info.log_ip or  _update_rule['log_ip'] or "127.0.0.1"
		_config_info.log_port = _config_info.log_port or  _update_rule['log_port'] or "5555"
		_config_info.log_sock_type = _config_info.log_sock_type or  _update_rule['log_sock_type'] or "udp"
		_config_info.log_flush_limit = _config_info.log_flush_limit or  _update_rule['log_flush_limit'] or "1"
		_config_info.cookie_safe = _config_info.cookie_safe or _update_rule['cookie_safe'] or "true"
		_config_info.cookie_safe_client_ip = _config_info.cookie_safe_client_ip or _update_rule['cookie_safe_client_ip'] or "true"
		_config_info.cookie_safe_is_safe = _config_info.cookie_safe_is_safe or _update_rule['cookie_safe_is_safe'] or "false"
		_config_info.aes_random_key = _config_info.aes_random_key or _update_rule['aes_random_key'] or  str.to_hex(resty_random.bytes(8))
		_config_info.observ_mode =  _config_info.observ_mode or _update_rule['observ_mode'] or "false"
		_config_info.resp_engine =  _config_info.resp_engine or _update_rule['resp_engine'] or "false"
		_config_info.limitreq_engine = _config_info.limitreq_engine or _update_rule['cc_engine'] or "false"
		_config_info.geo_protection = _config_info.geo_protection or _update_rule['geo_protection'] or "false"
		_config_info.template_status = _config_info.template_status or _update_rule['template_status'] or "false"
		_config_info.template_name = _config_info.template_name or _update_rule['template_name'] or "null"
		_config_info.template_type = _config_info.template_type or _update_rule['template_type'] or "null"
		_config_info.template_content = _config_info.template_content or _update_rule['template_content'] or "null"

		if _config_info.base_engine == "true" then
			ngx.log(ngx.ALERT,"success load global config base_engine: Open")
		else
			ngx.log(ngx.ALERT,"success load global config base_engine: Shutdown")
		end

		if _config_info.limitreq_engine == "true" then
			ngx.log(ngx.ALERT,"success load global config limitreq_engine: Open")
		else
			ngx.log(ngx.ALERT,"success load global config limitreq_engine: Shutdown")
		end

		if _config_info.geo_protection == "true" then
			if not geo.initted() then
				local res, err = geo.init(_config_geo_path)
				if err then
					ngx.log(ngx.ERR,err)
				end
				ngx.log(ngx.ALERT,"success load global config geo_engine: Open")
			end

			if not geo.initted() then
				ngx.log(ngx.ALERT,"success load global config geo_engine: Shutdown")
			end
		else
			ngx.log(ngx.ALERT,"success load global config geo_engine: Shutdown")
		end

		if _config_info.base_engine == "true" or _config_info.resp_engine == "true" or _config_info.limitreq_engine == "true" then
			_base_update_rule()
		end
	else
		--ngx.log(ngx.ERR, read_body)
		ngx.log(ngx.ERR,"init fail,can not decode remote_global_rule")
		--如果读取不到线上配置，则读取本机全局配置文件
		_global_local_update_rule()
		if _config_info.base_engine == "true" or _config_info.resp_engine == "true" or _config_info.limitreq_engine == "true" then
			_base_update_rule()
		end
	end
end


function _M.init_worker()
	-- 初始化更新线上全局变量
	if _config_info.waf_local == "false" then
		local global_ok, global_err = ngx.timer.at(0,_global_update_rule)
		if not global_ok then
			ngx.log(ngx.ERR, "failed to create the global timer: ", global_err)
		end
	end
end


function _M.init(config_path)
	-- 初始化全局配置
	local init_config_path = config_path or _config_path
	local read_config = assert(io.open(init_config_path,'r'))
	local raw_config_info = read_config:read('*all')
	read_config:close()
	local config_info = cjson.decode(raw_config_info)
	if config_info ~= nil then
		_config_info = config_info
		if _config_info.waf_local == "true" then
			-- 本地全局配置
			_global_local_update_rule()
			-- 本地规则配置文件
			if _config_info.base_engine == "true" or _config_info.resp_engine == "true" or _config_info.limitreq_engine == "true" then
				_local_base_update_rule(_local_base_config_path)
			end
		end
	else
		ngx.log(ngx.ERR,"init fail,can not decode localhost_config_file")
	end
end


function _M.get_config_info()
	local config_info = _config_info
	return config_info
end

function _M.get_resp_rule()
	return  _resp_rules
end

function _M.base_check()
	-- 决策引擎
	if _config_info.base_engine == "true" then
		local rules = _rules
		if  #rules == 0 then
			ngx.log(ngx.CRIT,"No WAF rules are found.")
			return
		end
		local result,rule = _rule_match(rules)
		if result then
			if rule.rule_action == 'deny' then
				--阻断请求
				if _config_info.template_status == "true" then
					ngx.header.content_type = _config_info.template_type
					ngx.say(string.format(_config_info.template_content, ngx.var.remote_addr ))
					ngx.exit(ngx.HTTP_OK)
				else
					ngx.exit(511)
				end
			elseif rule.rule_action == 'allow' then
				--放行请求(跳过所有后续规则,resp阶段不适用)
				ngx.exit(0)
			elseif rule.rule_action == 'redirect' then
				--重定向请求(resp阶段不适用)
				ngx.redirect(_config_info.http_redirect)
			elseif rule.rule_action == 'rewrite' then
				--重写整个页面
				--ngx.ctx.resp_action = "rewrite"
				--ngx.ctx.resp_rewrite_data = rule.rule_action_data
				ngx.header["Content-Type"] = "text/html; charset=utf-8"
				ngx.say(ngx.decode_base64(rule.rule_action_data))
			elseif rule.rule_action == 'inject_js' then
				--插入js/html代码
				ngx.ctx.resp_action = "inject_js"
				ngx.ctx.resp_inject_js_data = rule.rule_action_data
			elseif rule.rule_action == "replace" then
				--替换匹配内容
				ngx.ctx.resp_action = "replace"
				ngx.ctx.resp_replace_check = rule.rule_action_data
				ngx.ctx.resp_replace_data = rule.rule_action_replace_data
			else
				ngx.log(ngx.ERR,"rule action ERR!")
			end
		end
	end
end


local function _limit_req_log(rule)
	local conf_platform_tag = _config_info.waf_platform_tag
	local rule_id = rule.rule_id
	local rule_detail = rule.rule_detail
	local ctx_limit_log = {}
	ctx_limit_log.log_type = "cc_log"
	ctx_limit_log.platform_tag = conf_platform_tag
	ctx_limit_log.rule_id = rule_id
	ctx_limit_log.rule_detail = rule_detail
	ctx_limit_log.uri = ngx.var.uri
	ctx_limit_log.remote_addr = ngx.var.remote_addr
	return ctx_limit_log
end


local function _limitreq_check(limit_rules)
	-- limit 请求处理
	--[[local process_key
	local limit_var = {}
	local observ_mode = _config_info.observ_mode
	if type(rule.rule_key_vars) == "table" then
		for _,var in ipairs(rule.rule_key_vars) do
			local process_request_var = _process_request(var)
			if type(process_request_var) == "table" then
				for _,v in pairs(process_request_var) do
					if type(v) == "table" then
						ngx.log(ngx.ERR,"LIMIT ERROR")
						ngx.exit(403)
					end
					table.insert( limit_var, v )
				end
			else
				table.insert( limit_var, process_request_var )
			end
		end
	end
	process_key = table.concat( limit_var )
	if rule.rule_global == "true" then ]]
	-- 全局CC处理引擎，在OWASP检测前执行CC拦截
	for _,rule in ipairs(limit_rules) do
		process_key = request.request['REMOTE_ADDR']()
		if rule.rule_action == "limit_req_pass" then
			--IP、URL、域名等白名单功能
			for _,match in ipairs(rule.rule_matchs) do
				for _,var in ipairs(match.rule_vars) do
					local process_request = _process_request(var) 	--参数选择
					local process_transform = _process_transform(process_request,match.rule_transform,var) --参数处理
					local _operator_result,_operator_value,_operator_key,captures = _process_operator(process_transform,match,var,rule)
					if _operator_result then
						--CC白名单，放行请求(跳过所有后续规则，包括OWASP规则,resp阶段不适用)
						return true
					end
				end
			end
		elseif rule.rule_action == "limit_req_rate" then
			limitreq.limit_req_rate(rule,_limit_req_log(rule),ngx.md5(process_key))
		elseif rule.rule_action == "limit_req_count" then
			limitreq.limit_req_count(rule,_limit_req_log(rule),ngx.md5(process_key))
		end
	end
end


function _M.limitreq_check()
	-- Speed limit rule CC防护引擎
	if _config_info.limitreq_engine == "true" then
		local limit_rules = _limit_req_rules
		if #limit_rules == 0 then
			ngx.log(ngx.CRIT, "Can Not Find Limitreq Rules. Limitreq Pass")
		else
			if _config_info.observ_mode == "false" then
				_limitreq_check(limit_rules)
			end
		end
	end
end


-- 访问地区限制
function _M.geo_protection()
	if _config_info.geo_protection == "true" then
		local res,err = geo.lookup(ngx.var.remote_addr)
		if res then
			if res.country.names.en ~= "China" then
				local geo_rule_log = request.request['HTTP_FULL_INFO']()
				geo_rule_log['log_type'] = "geo_log"
				geo_rule_log['rule_detail'] = "非中国地区限制"
				geo_rule_log['country'] = res.country.names.en
				geo_rule_log['platform_tag'] = _config_info.waf_platform_tag
				if _config_info.observ_mode == "false" then
					geo_rule_log['request_status'] = "拦截"
					ngx.ctx.geo_rule_log = geo_rule_log
					ngx.exit(512)
				else
					geo_rule_log['request_status'] = "放过"
					ngx.ctx.geo_rule_log = geo_rule_log
				end
			end
		end
	end
end


function _M.access_init()
	-- 参数初始化
	local content_type = ngx.req.get_headers()["Content-type"]
	if content_type and  ngx.re.find(content_type, [=[^multipart/form-data]=],"oij") and tonumber(ngx.req.get_headers()["Content-Length"]) ~= 0 then
		local form, err = upload:new()
		local _file_name = {}
		local _form_name = {}
		local _file_type = {}
		local t ={}
		local _type_flag = "false"
		if not form then
			ngx.log(ngx.ERR, "failed to new upload: ", err)
			ngx.exit(500)
		end
		ngx.req.init_body()
		ngx.req.append_body("--" .. form.boundary)
		local lasttype, chunk
		local count = 0
		while true do
			count = count + 1
			local typ, res, err = form:read()
                if not typ then
                    ngx.say("failed to read: ", err)
                	return nil
                end
				if typ == "header" then
				--	chunk = res[3]
				--	ngx.req.append_body("\r\n" .. chunk)
                    if res[1] == "Content-Disposition" then
                    	local _tmp_form_name = ngx.re.match(res[2],[=[(.+)\bname=[" ']*?([^"]+)[" ']*?]=],"oij")
						local _tmp_file_name =  ngx.re.match(res[2],[=[(.+)filename=[" ']*?([^"]+)[" ']*?]=],"oij")
                    	if _tmp_form_name  then
                        	table.insert(_form_name,_tmp_form_name[2]..count)
						end

						if _tmp_file_name  then
							table.insert(_file_name,_tmp_file_name[2])
						end

						if _tmp_form_name and _tmp_file_name then
							chunk = string.format([=[Content-Disposition: form-data; name="%s"; filename="%s"]=],_tmp_form_name[2],_tmp_file_name[2])
							ngx.req.append_body("\r\n" .. chunk)
						elseif _tmp_form_name then
							chunk = string.format([=[Content-Disposition: form-data; name="%s"]=],_tmp_form_name[2])
							 ngx.req.append_body("\r\n" .. chunk)
						else
							ngx.log(ngx.ERR,"Content-Disposition ERR!")
							ngx.exit(503)
						end

                	end
                	if res[1] == "Content-Type" then
                    	table.insert(_file_type,res[2])
						_type_flag = "true"
						chunk = string.format([=[Content-Type: %s]=],res[2])
						ngx.req.append_body("\r\n" .. chunk)
                	end
				end
			if typ == "body" then
					chunk = res
					if lasttype == "header" then
						ngx.req.append_body("\r\n\r\n")
					end

					ngx.req.append_body(chunk)
					if _type_flag == "true" then
						_type_flag = "false"
						t[_form_name[#_form_name]] = ""
					else
						if lasttype == "header" then
							t[_form_name[#_form_name]] = res
						else
							t[_form_name[#_form_name]] = ""
						end
                    end
			end
				if typ == "part_end" then
					ngx.req.append_body("\r\n--" .. form.boundary)
				end

				if typ == "eof" then
					ngx.req.append_body("--\r\n")
					break
				end
				lasttype = typ
		end
		form:read()
		ngx.req.finish_body()
		ngx.ctx.form_post_args = t
		ngx.ctx.form_file_name = _file_name
		ngx.ctx.form_file_type = _file_type
	else
		ngx.req.read_body()
	end
end

function _M.resp_header_chunk()
	return _resp_header_chunk
end

return _M
