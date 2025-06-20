-- nas-utils.jwt.lua
-- TODO: Switch alg to HS512, add iat, nbf, sub and iss claims

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


--[[

https://datatracker.ietf.org/doc/html/rfc7519

Internet Engineering Task Force (IETF)                          M. Jones
Request for Comments: 7519                                     Microsoft
Category: Standards Track                                     J. Bradley
ISSN: 2070-1721                                            Ping Identity
                                                             N. Sakimura
                                                                     NRI
                                                                May 2015


                          JSON Web Token (JWT)

Abstract

   JSON Web Token (JWT) is a compact, URL-safe means of representing
   claims to be transferred between two parties.  The claims in a JWT
   are encoded as a JSON object that is used as the payload of a JSON
   Web Signature (JWS) structure or as the plaintext of a JSON Web
   Encryption (JWE) structure, enabling the claims to be digitally
   signed or integrity protected with a Message Authentication Code
   (MAC) and/or encrypted.

Example JWT

   The following example JOSE Header declares that the encoded object is
   a JWT, and the JWT is a JWS that is MACed using the HMAC SHA-256
   algorithm:

     {"typ":"JWT",
      "alg":"HS256"}

4.1.  Registered Claim Names

   The following Claim Names are registered in the IANA "JSON Web Token
   Claims" registry established by Section 10.1.  None of the claims
   defined below are intended to be mandatory to use or implement in all
   cases, but rather they provide a starting point for a set of useful,
   interoperable claims.  Applications using JWTs should define which
   specific claims they use and when they are required or optional.  All
   the names are short because a core goal of JWTs is for the
   representation to be compact.

4.1.1.  "iss" (Issuer) Claim

   The "iss" (issuer) claim identifies the principal that issued the
   JWT.  The processing of this claim is generally application specific.
   The "iss" value is a case-sensitive string containing a StringOrURI
   value.  Use of this claim is OPTIONAL.

4.1.2.  "sub" (Subject) Claim

   The "sub" (subject) claim identifies the principal that is the
   subject of the JWT.  The claims in a JWT are normally statements
   about the subject.  The subject value MUST either be scoped to be
   locally unique in the context of the issuer or be globally unique.
   The processing of this claim is generally application specific.  The
   "sub" value is a case-sensitive string containing a StringOrURI
   value.  Use of this claim is OPTIONAL.

4.1.3.  "aud" (Audience) Claim

   The "aud" (audience) claim identifies the recipients that the JWT is
   intended for.  Each principal intended to process the JWT MUST
   identify itself with a value in the audience claim.  If the principal
   processing the claim does not identify itself with a value in the
   "aud" claim when this claim is present, then the JWT MUST be
   rejected.  In the general case, the "aud" value is an array of case-
   sensitive strings, each containing a StringOrURI value.  In the
   special case when the JWT has one audience, the "aud" value MAY be a
   single case-sensitive string containing a StringOrURI value.  The
   interpretation of audience values is generally application specific.
   Use of this claim is OPTIONAL.

4.1.4.  "exp" (Expiration Time) Claim

   The "exp" (expiration time) claim identifies the expiration time on
   or after which the JWT MUST NOT be accepted for processing.  The
   processing of the "exp" claim requires that the current date/time
   MUST be before the expiration date/time listed in the "exp" claim.
   Implementers MAY provide for some small leeway, usually no more than
   a few minutes, to account for clock skew.  Its value MUST be a number
   containing a NumericDate value.  Use of this claim is OPTIONAL.

4.1.5.  "nbf" (Not Before) Claim

   The "nbf" (not before) claim identifies the time before which the JWT
   MUST NOT be accepted for processing.  The processing of the "nbf"
   claim requires that the current date/time MUST be after or equal to
   the not-before date/time listed in the "nbf" claim.  Implementers MAY
   provide for some small leeway, usually no more than a few minutes, to
   account for clock skew.  Its value MUST be a number containing a
   NumericDate value.  Use of this claim is OPTIONAL.

4.1.6.  "iat" (Issued At) Claim

   The "iat" (issued at) claim identifies the time at which the JWT was
   issued.  This claim can be used to determine the age of the JWT.  Its
   value MUST be a number containing a NumericDate value.  Use of this
   claim is OPTIONAL.

4.1.7.  "jti" (JWT ID) Claim

   The "jti" (JWT ID) claim provides a unique identifier for the JWT.
   The identifier value MUST be assigned in a manner that ensures that
   there is a negligible probability that the same value will be
   accidentally assigned to a different data object; if the application
   uses multiple issuers, collisions MUST be prevented among values
   produced by different issuers as well.  The "jti" claim can be used
   to prevent the JWT from being replayed.  The "jti" value is a case-
   sensitive string.  Use of this claim is OPTIONAL.


5.  JOSE Header

   For a JWT object, the members of the JSON object represented by the
   JOSE Header describe the cryptographic operations applied to the JWT
   and optionally, additional properties of the JWT.  Depending upon
   whether the JWT is a JWS or JWE, the corresponding rules for the JOSE
   Header values apply.

   This specification further specifies the use of the following Header
   Parameters in both the cases where the JWT is a JWS and where it is a
   JWE.

5.1.  "typ" (Type) Header Parameter

   The "typ" (type) Header Parameter defined by [JWS] and [JWE] is used
   by JWT applications to declare the media type [IANA.MediaTypes] of
   this complete JWT.  This is intended for use by the JWT application
   when values that are not JWTs could also be present in an application
   data structure that can contain a JWT object; the application can use
   this value to disambiguate among the different kinds of objects that
   might be present.  It will typically not be used by applications when
   it is already known that the object is a JWT.  This parameter is
   ignored by JWT implementations; any processing of this parameter is
   performed by the JWT application.  If present, it is RECOMMENDED that
   its value be "JWT" to indicate that this object is a JWT.  While
   media type names are not case sensitive, it is RECOMMENDED that "JWT"
   always be spelled using uppercase characters for compatibility with
   legacy implementations.  Use of this Header Parameter is OPTIONAL.

5.2.  "cty" (Content Type) Header Parameter

   The "cty" (content type) Header Parameter defined by [JWS] and [JWE]
   is used by this specification to convey structural information about
   the JWT.

   In the normal case in which nested signing or encryption operations
   are not employed, the use of this Header Parameter is NOT
   RECOMMENDED.  In the case that nested signing or encryption is
   employed, this Header Parameter MUST be present; in this case, the
   value MUST be "JWT", to indicate that a Nested JWT is carried in this
   JWT.  While media type names are not case sensitive, it is
   RECOMMENDED that "JWT" always be spelled using uppercase characters
   for compatibility with legacy implementations.  See Appendix A.2 for
   an example of a Nested JWT.

5.3.  Replicating Claims as Header Parameters

   In some applications using encrypted JWTs, it is useful to have an
   unencrypted representation of some claims.  This might be used, for
   instance, in application processing rules to determine whether and
   how to process the JWT before it is decrypted.

   This specification allows claims present in the JWT Claims Set to be
   replicated as Header Parameters in a JWT that is a JWE, as needed by
   the application.  If such replicated claims are present, the
   application receiving them SHOULD verify that their values are
   identical, unless the application defines other specific processing
   rules for these claims.  It is the responsibility of the application
   to ensure that only claims that are safe to be transmitted in an
   unencrypted manner are replicated as Header Parameter values in the
   JWT.

   Section 10.4.1 of this specification registers the "iss" (issuer),
   "sub" (subject), and "aud" (audience) Header Parameter names for the
   purpose of providing unencrypted replicas of these claims in
   encrypted JWTs for applications that need them.  Other specifications
   MAY similarly register other names that are registered Claim Names as
   Header Parameter names, as needed.

6.  Unsecured JWTs

   To support use cases in which the JWT content is secured by a means
   other than a signature and/or encryption contained within the JWT
   (such as a signature on a data structure containing the JWT), JWTs
   MAY also be created without a signature or encryption.  An Unsecured
   JWT is a JWS using the "alg" Header Parameter value "none" and with
   the empty string for its JWS Signature value, as defined in the JWA
   specification [JWA]; it is an Unsecured JWS with the JWT Claims Set
   as its JWS Payload.

6.1.  Example Unsecured JWT

   The following example JOSE Header declares that the encoded object is
   an Unsecured JWT:

     {"alg":"none"}

7.2.  Validating a JWT

   When validating a JWT, the following steps are performed.  The order
   of the steps is not significant in cases where there are no
   dependencies between the inputs and outputs of the steps.  If any of
   the listed steps fail, then the JWT MUST be rejected -- that is,
   treated by the application as an invalid input.

   1.   Verify that the JWT contains at least one period ('.')
        character.

   2.   Let the Encoded JOSE Header be the portion of the JWT before the
        first period ('.') character.

   3.   Base64url decode the Encoded JOSE Header following the
        restriction that no line breaks, whitespace, or other additional
        characters have been used.

   4.   Verify that the resulting octet sequence is a UTF-8-encoded
        representation of a completely valid JSON object conforming to
        RFC 7159 [RFC7159]; let the JOSE Header be this JSON object.

   5.   Verify that the resulting JOSE Header includes only parameters
        and values whose syntax and semantics are both understood and
        supported or that are specified as being ignored when not
        understood.

   6.   Determine whether the JWT is a JWS or a JWE using any of the
        methods described in Section 9 of [JWE].

   7.   Depending upon whether the JWT is a JWS or JWE, there are two
        cases:

        *  If the JWT is a JWS, follow the steps specified in [JWS] for
           validating a JWS.  Let the Message be the result of base64url
           decoding the JWS Payload.

        *  Else, if the JWT is a JWE, follow the steps specified in
           [JWE] for validating a JWE.  Let the Message be the resulting
           plaintext.

   8.   If the JOSE Header contains a "cty" (content type) value of
        "JWT", then the Message is a JWT that was the subject of nested
        signing or encryption operations.  In this case, return to Step
        1, using the Message as the JWT.

   9.   Otherwise, base64url decode the Message following the
        restriction that no line breaks, whitespace, or other additional
        characters have been used.

   10.  Verify that the resulting octet sequence is a UTF-8-encoded
        representation of a completely valid JSON object conforming to
        RFC 7159 [RFC7159]; let the JWT Claims Set be this JSON object.

   Finally, note that it is an application decision which algorithms may
   be used in a given context.  Even if a JWT can be successfully
   validated, unless the algorithms used in the JWT are acceptable to
   the application, it SHOULD reject the JWT.

]]