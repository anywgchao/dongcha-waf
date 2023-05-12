--[[
Author: Daboluo
Date: 2020-08-19 11:45:17
LastEditTime: 2020-08-19 23:11:22
LastEditors: Do not edit
--]]

local aes = require "resty.aes"
local str = require "resty.string"
local aes_256_cbc_sha512x5 = aes:new("AKeyFor-www1.DCsec.cn",
        "SecPass#", aes.cipher(256,"cbc"), aes.hash.sha512, 5)


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


local function _base64_encode(value)
    -- base64加密
    local val = ngx.encode_base64(value)
    return val
end


local function _base64_decode(value)
    -- base64解密
    local val = ngx.decode_base64(tostring(value))
    if (val) then
            return val
    else
            return value
    end
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

local expiration_time = "2020-09-27 19:48:57"
local encrypt_key = encrypt_sha512('www.dcsec.cn#' .. expiration_time)
local encrypted_hex_base64 = _base64_encode(encrypt_sha512('www.dcsec.cn#' .. expiration_time)..'#'..expiration_time)
ngx.say("AES 256 CBC (SHA-512, salted) Expiration time: ", expiration_time)
ngx.say("AES 256 CBC (SHA-512, salted) Encrypt key: ", encrypt_key)
ngx.say("AES 256 CBC (SHA-512, salted) Encrypted hex Base64: ", encrypted_hex_base64)

ngx.say("AES 256 CBC (SHA-512, salted) Split: ", '------------------------------------------------')
ngx.say("AES 256 CBC (SHA-512, salted) Decryption hex Base64: ", _base64_decode(encrypted_hex_base64))
