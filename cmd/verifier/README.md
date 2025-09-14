# tsidp verifier

The verifier is meant to be run like so:

```
$ go run . -sts -idp https://idp.ts0000.ts.net
```

## Testing Security Token Server (sts) RFC 8693

To test the Security Token Server in tsidp make sure an [application grant](https://tailscale.com/kb/1324/grants) has been set.

> [!NOTE]
> This is a very permissive grant. Recommended only for testing and development:

```
...
"grants": [
  {
    "src": ["*"],
    "dst": ["*"],
    "ip":  ["*"],

    "app": {
      "tailscale.com/cap/tsidp": [
        {
          "users":     ["*"],
          "resources": ["*"],
        },
      ],
    },
  },
...
```

## Output Example

```
Step 1: Fetching provider metadata from https://idp.ts001.ts.net...
✅ Success. Authorization Endpoint: https://idp.ts001.ts.net/authorize

Step 2: Dynamically registering a new client...
✅ Success. Registered Client ID: fbd8dfa7f58205920cec45320fd9f35e

Step 3: Awaiting user authorization...
Generated Authorization URL with state=Rb-LHoG2ANhIqCpoKGxiv2bi1HoC-Xp3L04qu6Isyws= and nonce=a6HGEBl0ifBl6W5x8pAQA-b8zKnHQxCXvCgb5lNeu8o=

Attempting to GET the authorization URL directly...
✅ Success: Provider sent a redirect. This is expected for the tsidp flow.

Step 4: Handling redirect and extracting parameters...
✅ Success. Received authorization code: 36412d452218d1e7126b...

Step 5: Exchanging code for tokens...
✅ Success. Received Access Token: fd8ab6d67d3423ad12ae...

(Critical Step) Verifying ID Token signature and claims...
✅ Signature is valid.
✅ All claims are valid.
✅ Success. ID Token is valid. User Subject (sub): userid:<redacted>

Step 6: Introspecting the access token...
✅ Success. Introspection response received.

Step 7: Calling userinfo endpoint...
✅ Success. UserInfo response received.

Step 8: Performing STS token exchange...
✅ Success. Received exchanged token: d7caca739d794734067d...

---------------------- OIDC FLOW COMPLETE ----------------------

✅ All steps completed successfully!

---------------------- OIDC FLOW COMPLETE ----------------------

✅ All steps completed successfully!

--- ID Token Claims ---
{
  "iss": "https://idp.ts001.ts.net",
  "sub": "userid:0001",
  "aud": [
    "bb136f58ee4838e95c93c0aaf92712e0"
  ],
  "exp": 1757562670,
  "iat": 1757562370,
  "nonce": "PCfK0jy6O3VF4onpNzz2T5sTIlZtQW_94TsQFYFfIbE=",
  "email": "",
  "name": ""
}

--- Introspection Response ---
{
  "active": true,
  "aud": [
    "bb136f58ee4838e95c93c0aaf92712e0"
  ],
  "client_id": "bb136f58ee4838e95c93c0aaf92712e0",
  "exp": 1757562670,
  "iat": 1757562370,
  "iss": "https://idp.ts001.ts.net",
  "jti": "1f3895486339092e61cf70fe46a62afc",
  "nbf": 1757562370,
  "sub": "7743467757367193",
  "token_type": "Bearer",
  "username": "<redacted>"
}

--- UserInfo Response ---
{
  "email": "<redacted>@tailscale.com",
  "name": "Some User",
  "picture": "https://lh3.googleusercontent.com/a/ACg8ocKBPEaUhLFl6CBXu9mfNUpe3I_mW8m-FBzHwVfEaSfklNwqQelz=s96-c",
  "sub": "<redacted>",
  "username": "my_username"
}
```
