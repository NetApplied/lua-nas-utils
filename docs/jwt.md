# nas-utils.jwt

A Lua module for creating and verifying JSON Web Tokens (JWT) using HMAC SHA256.

## Table of Contents

- [encode](#encode)
- [decode](#decode)
- [Usage Example](#usage-example)

---

## encode

**Create a JWT token from a payload and secret.**

```lua
NASJwt.encode(payload, secret)
```

- `payload` (`table`): Table of claims to encode (e.g., `{sub="user", exp=unix_time}`).
- `secret` (`string`): Secret key for HMAC SHA256 signing.
- **Returns:** `string?` Encoded JWT token, or `nil` on error.

---

## decode

**Decode and verify a JWT token.**

```lua
NASJwt.decode(token, secret)
```

- `token` (`string`): JWT token string.
- `secret` (`string`): Secret key for HMAC SHA256 verification.
- **Returns:** `boolean, table|string`  
  - `true, payload_table` if valid  
  - `false, error_message` if invalid

---

## Usage Example

```lua
local jwt = require("nas-utils.jwt")

local payload = {sub = "user123", exp = os.time() + 3600}
local secret = "mysecretkey"

local token = jwt.encode(payload, secret)
print(token)

local ok, data = jwt.decode(token, secret)
if ok then
  print("Payload:", data.sub)
else
  print("JWT error:", data)
end
```

---

## Notes

- The JWT header is always `{ typ = "JWT", alg = "HS256" }`.
- The payload can include standard claims such as `exp` (expiration, as a Unix timestamp).
- If `exp` is present and expired, `decode` returns `false, "Token has expired"`.

---

## License

MIT License

---

## Author

Michael Stephan, NetApplied Solutions
