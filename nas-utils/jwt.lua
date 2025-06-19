-- nas-utils.jwt.lua

local NASJwt      = {}

NASJwt._AUTHORS   = "Michael Stephan"
NASJwt._VERSION   = "0.3.2-1"
NASJwt._LICENSE   = "MIT License"
NASJwt._COPYRIGHT = "Copyright (c) 2025 NetApplied Solutions"

local json        = require 'cjson'
local hmac_hash        = require ("nas-utils.crypto").hmac_hash
local b64encode   = require("nas-utils.crypto").base64encode
local b64decode   = require("nas-utils.crypto").base64decode


local function hmac_sha256(secret, data)
    local algs = require("nas-utils").DigestType
    local digest = hmac_hash(algs.SHA256, secret, data)
    return b64encode(digest, true)
end


-- JWT encode
---@param payload table Payload data
---@param secret string Secret for hmac hashing
---@return string? jwt JWT token
function NASJwt.encode(payload, secret)
    if not secret or type(payload) ~= "table" then return nil end

    local header = { typ = "JWT", alg = "HS256" }

    local encoded_header = b64encode(json.encode(header), true)
    local encoded_payload = b64encode(json.encode(payload), true)

    if encoded_header == nil or encoded_payload == nil then return nil end

    local signing_input = encoded_header .. '.' .. encoded_payload
    local signature = hmac_sha256(secret, signing_input)

    return signing_input .. '.' .. signature
end


-- Decode JWT Token
---@param token string Valid JWT token
---@param secret string Secret for hmac hashing
---@return boolean status True if ok, false if error
---@return string data Payload or error message
function NASJwt.decode(token, secret)
    local parts = { token:match('([^%.]+)%.([^%.]+)%.([^%.]+)') }
    if #parts ~= 3 then
        return false, "Invalid token format"
    end

    local encoded_header, encoded_payload, signature = unpack(parts)

    if not encoded_header or not encoded_payload or not signature then
        return false, "Malformed token"
    end

    local signing_input = encoded_header .. '.' .. encoded_payload

    local expected_signature = hmac_sha256(secret, signing_input)
    if signature ~= expected_signature then
        return false, "Invalid token signature"
    end

    local header = json.decode(b64decode(encoded_header, true) or "{}")
    local payload = json.decode(b64decode(encoded_payload, true) or "{}")

    if header.typ ~= "JWT" or header.alg ~= "HS256" then
        return false, "Invalid token type or algorithm"
    end

    if payload.exp and os.time() > payload.exp then
        return false, "Token has expired"
    end

    return true, payload
end

return NASJwt
