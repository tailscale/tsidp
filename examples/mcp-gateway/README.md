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

## 1) Run tsidp with the `--enable-sts` flag set

If running via docker, it should look something like this:

```bash
docker run -d \
  --name tsidp \
  -p 443:443 \
  -e TS_AUTHKEY=YOUR_TAILSCALE_AUTHKEY \
  -e TSNET_FORCE_LOGIN=1
  -e TAILSCALE_USE_WIP_CODE=1 \
  -v tsidp-data:/var/lib/tsidp \
  tsidp --hostname=idp --dir=/var/lib/tsidp --enable-sts
```

## 2) Update the ACL rules on your tailnet

To allow token exchange you’ll also need to add an [ACL application grant](https://tailscale.com/kb/1537/grants-app-capabilities)  rule to your tailnet that allows a given user and / or device the ability to exchange tokens for other resources. The following rule is extra permissive for this demo, but it allows anyone from any device on the tailnet to exchange tokens for the audiences of `http://localhost:8003` and `http://localhost:8001`

```json
{
  "src": ["*"],
  "dst": ["*"],
  "app": {
    "tailscale.com/cap/tsidp": [
      {
        "users":     ["*"],
        "resources": ["http://localhost:8003", "http://localhost:8001"],
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

It’s recommended that you install `uv` to run the python examples.

## 4) Run the server

In a new terminal window run the server using the following command. It should start on `localhost` port `8001`.

```bash
cd server
uv run mcp-auth-server --auth-server-url https://idp.YOUR_TAILNET.ts.net/
```

## 5) Run the gateway

In a new terminal window run the gateway using the following command. It should start on `localhost` port `8003`.

```bash
cd gateway
uv run mcp-auth-gateway --auth-server-url https://idp.YOUR_TAILNET.ts.net/ --mcp-server-url http://localhost:8001
```

## 6) Run the client

In a new terminal window run the client using the following command. If successful it should pop up an authorization callback.

```bash
cd client
uv run mcp-auth-client http://localhost:8003/mcp
```

## 7) Make a tool call

If everything was successful, you should be able to list the tools available on the server (via the gateway). In addition, you can call the `oauth_details` tool to see the token as the server received it.
