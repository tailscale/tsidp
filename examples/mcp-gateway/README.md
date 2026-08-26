# MCP Gateway Pattern

The code in this directory provides a working example of using tsidp with an MCP client, gateway, and server. To support this pattern tsidp implements both [Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591) and [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693).

On start up, the client, gateway, and server each register themselves as OAuth clients with tsidp so they can perform both authentication, exchange, and introspection of tokens. The pattern works as follows:

1. The MCP client registers itself with tsidp as an OAuth client.
2. The MCP client authorizes the user to then request an access token to access the MCP gateway.
3. The MCP gateway also registers itself with tsidp as an OAuth client.
4. However, instead of authorizing the user it takes the token presented to it by the MCP client and then exchanges the token (of which it was the original audience) for a token with the MCP server as the audience.
5. The MCP server also registers itself with tsidp. However, this is only to perform a final introspection of the token to ensure it is valid and the MCP server is listed as the audience rather than the previously listed MCP gateway.
6. Once validated the MCP server initiates the MCP connection back to the gateway and subsequently the client.

To run this example you’ll need to do the following:

## 1) Run tsidp

Using the latest docker container is recommended:

```bash
$ docker run -it --rm --name tsidp \
  -v tsidp-mcp-gateway-demo:/data \
  -e TS_STATE_DIR=/data \
  -e TS_HOSTNAME=tsidp-mcp-gateway-demo \
  -e TSIDP_ENABLE_STS=1 \
  -e TAILSCALE_USE_WIP_CODE=1 \
  -e TSIDP_LOG=debug ghcr.io/tailscale/tsidp:latest

2025/12/03 18:36:18 tsnet running state path /data/tailscaled.state
2025/12/03 18:36:18 tsnet starting with hostname "tsidp-mcp-gateway-demo", varRoot "/data"
2025/12/03 18:36:18 LocalBackend state is NeedsLogin; running StartLoginInteractive...
2025/12/03 18:36:23 To start this tsnet server, restart with TS_AUTHKEY set, or go to: https://login.tailscale.com/a/abcd123456789
2025/12/03 18:36:44 INFO tsidp server started server_url=https://tsidp-mcp-gateway-demo.<YOUR-TAILNET>.ts.net
2025/12/03 18:36:48 AuthLoop: state is Running; done
```

## 2) Update the ACL rules on your tailnet

To allow token exchange you’ll also need to add an [ACL application grant](https://tailscale.com/kb/1537/grants-app-capabilities) rule to your tailnet that allows a given user and / or device the ability to exchange tokens for other resources. The following rule is extra permissive for this demo, but it allows anyone from any device on the tailnet to exchange tokens for the audiences of `http://localhost:8003` and `http://localhost:8001`

```json
{
  "src": ["*"],
  "dst": ["*"],
  "app": {
    "tailscale.com/cap/tsidp": [
      {
        "users":     ["*"],

        // enable STS and dynamic client registration
        "resources": ["http://localhost:8003", "http://localhost:8001"],
        "allow_dcr": true,
      },
    ],
  },
},
```

## 3) Clone the tsidp repo and open the example directory

```bash
git clone https://github.com/tailscale/tsidp.git
cd tsidp/examples/mcp-gateway/
```

It’s recommended that you install `uv` to run the python examples. This demo
also requires you to run an MCP server, gateway and client. This is easiest if
you have them running in their own terminal windows.

## 4) Run the MCP server

In a new terminal window run the server using the following command. It should start on `localhost` port `8001`.

```bash
cd server
$ uv run mcp-auth-server --auth-server-url https://tsidp-mcp-gateway-demo.<YOUR-TAILNET>.ts.net/
2025-12-03 10:43:59,271 - INFO - Creating MCP server with required scopes: ['openid']
2025-12-03 10:43:59,271 - INFO - Token verifier endpoint: https://tsidp-mcp-gateway-demo.<YOUR-TAILNET>.ts.net/introspect
2025-12-03 10:43:59,271 - INFO - Resource server URL: http://localhost:8001
2025-12-03 10:43:59,280 - INFO - MCP server ready - OAuth client: <CLIENT_ID>
2025-12-03 10:43:59,280 - INFO - Server will require scopes: ['openid']
2025-12-03 10:43:59,280 - INFO - Discovery endpoints available at http://localhost:8001/.well-known/
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
2025-12-03 10:43:59,296 - INFO - StreamableHTTP session manager started
INFO:     Application startup complete.
INFO:     Uvicorn running on http://localhost:8001 (Press CTRL+C to quit)
...
```

## 5) Run the MCP gateway

In a new terminal window run the gateway using the following command. It should start on `localhost` port `8003`.

```bash
cd gateway
$ uv run mcp-auth-gateway --auth-server-url https://tsidp-mcp-gateway-demo.<YOUR-TAILNET>.ts.net/ --mcp-server-url http://localhost:8001
MCP Auth Gateway v0.1.0
Authorization Server: https://tsidp-mcp-gateway-demo.<YOUR-TAILNET>.ts.net/
MCP Server: http://localhost:8001
Gateway URL: http://localhost:8003

...
```

## 6) Run the MCP client

In a new terminal window run the client using the following command. If successful it should pop up an authorization callback.

```bash
cd client
uv run mcp-auth-client http://localhost:8003/mcp
```

## 7) Make a tool call

If everything was successful, you should be able to list the tools available on the server (via the gateway). In addition, you can call the `oauth_details` tool to see the token as the server received it.

Example in the tool:

```
mcp>: list
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Tool          ┃ Description                                                         ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ debug_auth    │ Debug authentication by showing both header and context token info. │
│               │                                                                     │
│               │ This tool helps diagnose authentication issues by displaying        │
│               │ what token is in the Authorization header vs what's in the context. │
│               │                                                                     │
│               │ Returns:                                                            │
│               │     Dictionary with detailed auth debugging information             │
│               │                                                                     │
│ multiply      │ Multiply two numbers.                                               │
│               │                                                                     │
│               │ This tool requires OAuth authentication and returns the product     │
│               │ of two input numbers along with authentication context.             │
│               │                                                                     │
│               │ Args:                                                               │
│               │     a: First number to multiply                                     │
│               │     b: Second number to multiply                                    │
│               │                                                                     │
│               │ Returns:                                                            │
│               │     Dictionary with result and authentication info                  │
│               │                                                                     │
│ oauth_details │ Get OAuth authentication details for the current client.            │
│               │                                                                     │
│               │ Returns all available OAuth token information that the server       │
│               │ knows about the authenticated client.                               │
│               │                                                                     │
│               │ Returns:                                                            │
│               │     Dictionary with OAuth client and token details                  │
│               │                                                                     │
└───────────────┴─────────────────────────────────────────────────────────────────────┘

mcp>: call oauth_details
{
  "authenticated": true,
  "client_id": "8cc2afcec17ed1928086b1c8d4587dac",
  "scopes": [
    "openid",
    "profile",
    "email"
  ],
  "expires_at": 1764789340,
  "resource": "http://localhost:8001",
  "request_id": "6",
  "token_type": "Bearer",
  "current_time": 1764789300,
  "time_until_expiry": 40,
  "is_expired": false,
  "token_preview": "e5d3ea8a...5d8e699d"
}

mcp>: call multiply {"a":2,"b":4}
{
  "operation": "multiplication",
  "inputs": {
    "a": 2.0,
    "b": 4.0
  },
  "result": 8.0,
  "authenticated_as": "8cc2afcec17ed1928086b1c8d4587dac",
  "request_id": "5"
}
```
