local _M = {}
local limit_req = require "resty.limit.req"
local limit_count = require "resty.limit.count"
_M.version = "1.0"


function _M.limit_req_rate(rule,limit_req_log,process_key)
	-- 速率检测，支持延时
	local limit_store = "limit_req"
	local rate = tonumber(rule.rule_rate_or_count)
	local burst = tonumber(rule.rule_burst_or_time)
	local key = process_key
	local limit_log = limit_req_log
	local nodelay = rule.rule_nodelay
	local rule_limit_log = rule.rule_log

	-- 限制 ip 每分钟只能调用 N 次 接口（平滑处理请求，即每秒放过rate个请求，例如：400），超过部分进入桶中等待，（桶容量为burst，例如：50），如果桶也满了，则进行限流
	local lim, err = limit_req.new(limit_store, rate, burst)
	if not lim then
		ngx.log(ngx.ERR,"failed to instantiate a resty.limit.req object: ", err," limit_store is: ",limit_store)
		return ngx.exit(500)
	end

	--触发新请求传入事件并计算当前请求对指定 key 所需的 delay
	local delay, err = lim:incoming(key, true)
	if not delay then
		if err == "rejected" then
			if rule_limit_log == "true" then
				limit_log.rule_err = err
				ngx.ctx.rule_limit_reject_log = limit_log
			end
			-- 观察模式则放过
			return ngx.exit(513)
		end
		ngx.log(ngx.ERR, "failed to limit req: ", err)
		return ngx.exit(523)
	end

	-- 触发CC后，再延时0.001秒并则记录日志
	if nodelay == "true" then
	else
		local excess = err
		if rule_limit_log == "true" and delay >= 0.001 then
			limit_log.rule_excess = excess
			ngx.ctx.rule_limit_reject_log = limit_log
		end
		if delay >= 0.001 then
			ngx.sleep(delay)
		end
	end
end


function _M.limit_req_count(rule,limit_req_log,process_key)
	-- 单位时间总数量限制
	local limit_store = "limit_req_count"
	local count = tonumber(rule.rule_rate_or_count)
	local time = tonumber(rule.rule_burst_or_time)
	local key = process_key
	local limit_log = limit_req_log
	local rule_limit_log = rule.rule_log

	-- rate: 5000 requests per 3600s 单位时间内总数
	local lim, err = limit_count.new(limit_store, count, time)
	if not lim then
		ngx.log(ngx.ERR,"failed to instantiate a resty.limit.count object: ", err," limit_store is: ",limit_store)
		return	ngx.exit(500)
	end

	--触发新请求传入事件并计算当前请求对指定 key 所需的 delay
	local delay, err = lim:incoming(key, true)
	if not delay then
		if err == "rejected" then
			if rule_limit_log == "true" then
				limit_log.rule_err = err
				ngx.ctx.rule_limit_reject_log = limit_log
			end
			return ngx.exit(513)
		end
		ngx.log(ngx.ERR, "failed to limit count: ", err)
		return ngx.exit(523)
	end
end

return _M
