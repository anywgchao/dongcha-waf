--[[
Author: Daboluo
Date: 2020-08-19 11:45:17
LastEditTime: 2020-08-24 23:27:46
LastEditors: Do not edit
--]]


local cjson = require "cjson.safe"
local aes = require "resty.aes"
local str = require "resty.string"
local aes_256_cbc_sha512x5 = aes:new("AKeyFor-www1.DCsec.cn",
        "SecPass#", aes.cipher(256,"cbc"), aes.hash.sha512, 5)
local _M = {}
_M.version = "1.0"


local function _base64_decode(value)
    local val = ngx.decode_base64(tostring(value))
    if (val) then
        return val
    else
        return value
    end
end


local function _base64_encode(value)
    local val = ngx.encode_base64(value)
    return val
end


local function hex2bin(hexstr)
    -- 需要自己写一个函数将16进制转2进制
    local str = ""
    for i = 1, string.len(hexstr) - 1, 2 do
        local doublebytestr = string.sub(hexstr, i, i+1);
        local n = tonumber(doublebytestr, 16);
        if 0 == n then
            str = str .. '\00'
        else
            str = str .. string.format("%c", n)
        end
    end
    return str
end


local function encrypt_sha512(content)
    -- 加密函数,返回16进制
    local encrypteda = aes_256_cbc_sha512x5:encrypt(content)
    return str.to_hex(encrypteda)
end


local function dencrypt_sha512(content)
    --  解密函数 返回解密字符串
    local dencryptedb = aes_256_cbc_sha512x5:decrypt(hex2bin(content))
    return dencryptedb
end


local function file_exists(path)
    -- 读取lic文件内容
    local read_file = assert(io.open(path,'r'))
    local raw_config_info = read_file:read('*all')
    read_file:close()
    local config_info = cjson.decode(raw_config_info)
    local results = nil
    if config_info ~= nil then
        endDate = _base64_decode(config_info.waf_license)
        if endDate then string.find(endDate, "#")
            local t = string.split_lite(endDate, "#")
            if t[1] then
                results = t[1]
                return results
            end
        end
    end
    return results
end


local function timediff(now_time, end_time)
    --比较两个时间，返回相差多少时间
    local t = type(end_time)
    if t == "string" then
        --判断是string类型的话，转为number
        end_time = tonumber(end_time)
   end
   if now_time ~= nil and end_time ~= nil then
       -- 如果时间大于现在时间则为正常
       if now_time < end_time then
           return true
       end
   end
   return false
end


function string:split_lite(sep)
    --字符串分割函数
    local splits = {}

    if sep == nil then
        -- return table with whole str
        table.insert(splits, self)
    elseif sep == "" then
        -- return table with each single character
        local len = #self
        for i = 1, len do
            table.insert(splits, self:sub(i, i))
        end
    else
        -- normal split use gmatch
        local pattern = "[^" .. sep .. "]+"
        for str in string.gmatch(self, pattern) do
            table.insert(splits, str)
        end
    end

    return splits
end


function _M.license_check(license_path)
    -- 授权判断
    local results = false
    local endDate = file_exists(license_path)
    if endDate then
        local now_time = os.time()
        local endDate = dencrypt_sha512(endDate)
        if endDate then string.find(endDate, "#")
            local t = string.split_lite(endDate, "#")
            if t[2] then
                local _, _, y, m, d, _hour, _min, _sec = string.find(t[2], "(%d+)-(%d+)-(%d+)%s*(%d+):(%d+):(%d+)");
                --转化为时间戳
                local end_time = os.time({year=y, month = m, day = d, hour = _hour, min = _min, sec = _sec});
                results = timediff(now_time, end_time)
            end
        end
    end
    return results
end

return _M
