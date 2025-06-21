# nas-utils.jwt

A Lua module providing JSON Web Token (JWT) encode/decode utilities.

## Table of Contents

- [encode](#encode)
- [decode](#decode)
- [Supported Algorithms](#supported-algorithms)
- [Usage Example](#usage-example)
- [See Also](#see-also)

---

## encode

**Encode a JWT token.**

```lua
jwt.encode(payload, secret, jwt_alg)
```

- `payload` (`table`): Claims to encode.
- `secret` (`string`): Secret for HMAC.
- `jwt_alg` (`string?`): Algorithm: "HS256" (default) or "HS512".
- **Returns:** `string` JWT token.

**Default Claims:**
If not present in `payload`, the following are set:
- `iat`: Current time
- `nbf`: Current time
- `exp`: Current time + 2 hours
- `sub`: "anonymous"
- `iss`: "https://default.issuer.example.com"
- `aud`: "https://default.audience.example.com"

---

## decode

**Decode and verify a JWT token.**

```lua
local status, data = jwt.decode(token, secret, check_exp)
```

- `token` (`string`): JWT token.
- `secret` (`string`): Secret for HMAC.
- `check_exp` (`boolean?`): Check expiration (default: true).
- **Returns:**
  - `status` (`boolean`): true if valid, false if error
  - `data` (`table|string`): Payload table if valid, or error message if failure

**Error Cases:**
- Invalid format, header, or payload
- Invalid signature or algorithm
- Expired token (if `check_exp` is true)

---

## Supported Algorithms

- `HS256` — HMAC-SHA256 (default)
- `HS512` — HMAC-SHA512

---

## Usage Example

```lua
local jwt = require("nas-utils.jwt")

local token = jwt.encode({user_id = 123}, "mysecret")
local ok, payload = jwt.decode(token, "mysecret")
if ok then
  print(payload.user_id)
end
```

---

## See Also
- [nas-utils (overview)](./nas-utils.md)
- [crypto](./crypto.md)
- [strings](./strings.md)
- [helpers](./helpers.md)
- [logger_rolling_file](./logger_rolling_file.md)

---

## License

MIT License.  
Copyright (c) 2025 Net Applied Solutions, LLC.  
All rights reserved.
    
See [LICENSE](./LICENSE) for details.

