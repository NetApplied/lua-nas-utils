# jwt module

JSON Web Token (JWT) encode/decode utilities for Lua.

---

## API

### Encoding

#### `encode(payload, secret, jwt_alg?)`
Encode a JWT.

```lua
jwt.encode(payload, secret, jwt_alg?)
```
- `payload` (table): Claims to encode
- `secret` (string): Secret for HMAC
- `jwt_alg` (string, optional): `"HS256"` (default) or `"HS512"`
- Returns: (string) JWT token

##### Default Claims
If not present in `payload`, the following are set:
- `iat`: Current time
- `nbf`: Current time
- `exp`: Current time + 2 hours
- `sub`: "anonymous"
- `iss`: "https://default.issuer.example.com"
- `aud`: "https://default.audience.example.com"

---

### Decoding

#### `decode(token, secret, check_exp?)`
Decode and verify a JWT.

```lua
jwt.decode(token, secret, check_exp?)
```
- `token` (string): JWT token
- `secret` (string): Secret for HMAC
- `check_exp` (boolean, optional): Check expiration (default `true`)
- Returns: `(status, data)`
  - `status` (boolean): true if valid, false if error
  - `data` (table|string): Payload table if valid, or error message

##### Error Cases
- Invalid format, header, or payload
- Invalid signature or algorithm
- Expired token (if `check_exp` is true)

---

### Supported Algorithms
- `HS256` — HMAC-SHA256 (default)
- `HS512` — HMAC-SHA512

---

## Example

```lua
local jwt = require("nas-utils.jwt")

local token = jwt.encode({user_id = 123}, "mysecret")
local ok, payload = jwt.decode(token, "mysecret")
if ok then
  print(payload.user_id)
end
```

---

## See also
- [nas-utils (overview)](./nas-utils.md)
- [crypto](./crypto.md)
- [strings](./strings.md)
- [helpers](./helpers.md)
- [logger_rolling_file](./logger_rolling_file.md)
