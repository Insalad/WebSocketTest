local bit = bit32

local byte = string.byte
local char = string.char
local sub = string.sub
local band = bit.band
local bor = bit.bor
local bxor = bit.bxor
local lshift = bit.lshift
local rshift = bit.rshift
local tostring = tostring
local concat = table.concat
local rand = math.random
local type = type

local _M = {}

_M._VERSION = '0.12'

local types = {
    [0x0] = "continuation",
    [0x1] = "text",
    [0x2] = "binary",
    [0x8] = "close",
    [0x9] = "ping",
    [0xa] = "pong",
}

local str_buf_size = 4096
local str_buf = ""

local function get_string_buf(size)
    if size > str_buf_size then
        return string.rep("\0", size)
    end
    if str_buf == "" then
        str_buf = string.rep("\0", str_buf_size)
    end

    return str_buf
end

function _M.recv_frame(sock, max_payload_len, force_masking)
    local data, err = sock:Receive(2)
    if not data then
        return nil, nil, "failed to receive the first 2 bytes: " .. err
    end

    local fst, snd = byte(data, 1, 2)

    local fin = band(fst, 0x80) ~= 0
    if band(fst, 0x70) ~= 0 then
        return nil, nil, "bad RSV1, RSV2, or RSV3 bits"
    end

    local opcode = band(fst, 0x0f)

    if opcode >= 0x3 and opcode <= 0x7 then
        return nil, nil, "reserved non-control frames"
    end

    if opcode >= 0xb and opcode <= 0xf then
        return nil, nil, "reserved control frames"
    end

    local mask = band(snd, 0x80) ~= 0

    if force_masking and not mask then
        return nil, nil, "frame unmasked"
    end

    local payload_len = band(snd, 0x7f)

    if payload_len == 126 then
        local data, err = sock:Receive(2)
        if not data then
            return nil, nil, "failed to receive the 2 byte payload length: " .. (err or "unknown")
        end

        payload_len = bor(lshift(byte(data, 1), 8), byte(data, 2))

    elseif payload_len == 127 then
        local data, err = sock:Receive(8)
        if not data then
            return nil, nil, "failed to receive the 8 byte payload length: " .. (err or "unknown")
        end

        if byte(data, 1) ~= 0 or byte(data, 2) ~= 0 or byte(data, 3) ~= 0 or byte(data, 4) ~= 0 then
            return nil, nil, "payload len too large"
        end

        local fifth = byte(data, 5)
        if band(fifth, 0x80) ~= 0 then
            return nil, nil, "payload len too large"
        end

        payload_len = bor(lshift(fifth, 24), lshift(byte(data, 6), 16), lshift(byte(data, 7), 8), byte(data, 8))
    end

    if band(opcode, 0x8) ~= 0 then
        if payload_len > 125 then
            return nil, nil, "too long payload for control frame"
        end

        if not fin then
            return nil, nil, "fragmented control frame"
        end
    end

    if payload_len > max_payload_len then
        return nil, nil, "exceeding max payload len"
    end

    local rest
    if mask then
        rest = payload_len + 4
    else
        rest = payload_len
    end

    local data
    if rest > 0 then
        data, err = sock:Receive(rest)
        if not data then
            return nil, nil, "failed to read masking-len and payload: " .. (err or "unknown")
        end
    else
        data = ""
    end

    if opcode == 0x8 then
        if payload_len > 0 then
            if payload_len < 2 then
                return nil, nil, "close frame with a body must carry a 2-byte status code"
            end

            local msg, code
            if mask then
                local fst = bxor(byte(data, 4 + 1), byte(data, 1))
                local snd = bxor(byte(data, 4 + 2), byte(data, 2))
                code = bor(lshift(fst, 8), snd)

                if payload_len > 2 then
                    local bytes = get_string_buf(payload_len - 2)
                    for i = 3, payload_len do
                        bytes = bytes .. char(bxor(byte(data, 4 + i), byte(data, (i - 1) % 4 + 1)))
                    end
                    msg = bytes

                else
                    msg = ""
                end
            else
                local fst = byte(data, 1)
                local snd = byte(data, 2)
                code = bor(lshift(fst, 8), snd)

                if payload_len > 2 then
                    msg = sub(data, 3)

                else
                    msg = ""
                end
            end

            return msg, "close", code
        end

        return "", "close", nil
    end

    local msg
    if mask then
        local bytes = get_string_buf(payload_len)
        for i = 1, payload_len do
            bytes = bytes .. char(bxor(byte(data, 4 + i), byte(masking_key, (i - 1) % 4 + 1)))
        end
        msg = bytes
    else
        msg = data
    end

    return msg, types[opcode], not fin and "again" or nil
end

local function build_frame(fin, opcode, payload_len, payload, masking)
    local fst
    if fin then
        fst = bor(0x80, opcode)
    else
        fst = opcode
    end

    local snd, extra_len_bytes
    if payload_len <= 125 then
        snd = payload_len
        extra_len_bytes = ""

    elseif payload_len <= 65535 then
        snd = 126
        extra_len_bytes = char(band(rshift(payload_len, 8), 0xff), band(payload_len, 0xff))

    else
        if band(payload_len, 0x7fffffff) < payload_len then
            return nil, "payload too big"
        end

        snd = 127
        extra_len_bytes = char(0, 0, 0, 0, band(rshift(payload_len, 24), 0xff), band(rshift(payload_len, 16), 0xff), band(rshift(payload_len, 8), 0xff), band(payload_len, 0xff))
    end

    local masking_key
    if masking then
        snd = bor(snd, 0x80)
        local key = rand(0xffffffff)
        masking_key = char(band(rshift(key, 24), 0xff), band(rshift(key, 16), 0xff), band(rshift(key, 8), 0xff), band(key, 0xff))

        local bytes = get_string_buf(payload_len)
        for i = 1, payload_len do
            bytes = bytes .. char(bxor(byte(payload, i), byte(masking_key, (i - 1) % 4 + 1)))
        end
        payload = bytes
    else
        masking_key = ""
    end

    return char(fst, snd) .. extra_len_bytes .. masking_key .. payload
end
_M.build_frame = build_frame

function _M.send_frame(sock, fin, opcode, payload, max_payload_len, masking)
    if not payload then
        payload = ""
    elseif type(payload) ~= "string" then
        payload = tostring(payload)
    end

    local payload_len = #payload

    if payload_len > max_payload_len then
        return nil, "payload too big"
    end

    if band(opcode, 0x8) ~= 0 then
        if payload_len > 125 then
            return nil, "too much payload for control frame"
        end
        if not fin then
            return nil, "fragmented control frame"
        end
    end

    local frame, err = build_frame(fin, opcode, payload_len, payload, masking)
    if not frame then
        return nil, "failed to build frame: " .. err
    end

    local bytes, err = sock:Send(frame)
    if not bytes then
        return nil, "failed to send frame: " .. err
    end

    return bytes
end

return _M
