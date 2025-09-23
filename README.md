# `tsidp` - Tailscale OpenID Connect (OIDC) Identity Provider

> [!CAUTION]
> This is an experimental update of tsidp. It is under active development and may experince breaking changes.

[![status: community project](https://img.shields.io/badge/status-community_project-blue)](https://tailscale.com/kb/1531/community-projects)

`tsidp` is an OIDC / OAuth Identity Provider (IdP) server that integrates with your Tailscale network. It allows you to use Tailscale identities for authentication into applications that support OpenID Connect as well as authenticated MCP client / server connections.

## Prerequisites

- A Tailscale network (tailnet) with magicDNS and HTTPS enabled
- A Tailscale authentication key from your tailnet
- (Recommended) Docker installed on your system
- Ability to set an Application capability grant

## Running tsidp

### (Recommended) Using the pre-built image

To be updated.

### Other ways to build & run tsidp

<details>
<summary>Building your own container</summary>

Replace `YOUR_TAILSCALE_AUTHKEY` with your Tailscale authentication key in the following commands:

1. Use an existing auth key or create a new auth key in the [Tailscale dashboard](https://login.tailscale.com/admin/settings/keys). Ensure you select an existing [tag](https://tailscale.com/kb/1068/tags) or create a new one.

```bash
# Build the container using the included Dockerfile
docker build -t tsidp .

# Run tsidp with a persistent volume to store state
docker run -d \
  --name tsidp \
  -p 443:443 \
  -v tsidp-data:/data \
  -e TS_STATE_DIR=/data \
  -e TS_AUTHKEY=YOUR_TAILSCALE_AUTHKEY \
  -e TSNET_FORCE_LOGIN=1 \
  -e TAILSCALE_USE_WIP_CODE=1 \
  -e TSIDP_ENABLE_STS=1 \
  -e TS_HOSTNAME=idp \
  tsidp
```

Visit `https://idp.yourtailnet.ts.net` to confirm the service is running.

_If you're running tsidp for the first time, you may not be able to access it initially even though it is running. It takes a few minutes for the TLS certificate to generate._

</details>

<details>
<summary>Using Go directly</summary>

If you'd like to build tsidp and / or run it directly you can do the following:

```bash
# Clone the Tailscale repository
git clone https://github.com/tailscale/tsidp.git
cd tsidp
```

Replace `YOUR_TAILSCALE_AUTHKEY` with your Tailscale authentication key in the following commands:

1. Use an existing auth key or create a new auth key in the [Tailscale dashboard](https://login.tailscale.com/admin/settings/keys). Ensure you select an existing [tag](https://tailscale.com/kb/1068/tags) or create a new one.
2. Run `TS_AUTH_KEY=YOUR_TAILSCALE_AUTHKEY TAILSCALE_USE_WIP_CODE=1 TSNET_FORCE_LOGIN=1 go run .`

Visit `https://idp.yourtailnet.ts.net` to confirm the service is running.

_If you're running tsidp for the first time, you may not be able to access it initially even though it is running. It takes a few minutes for the TLS certificate to generate._

</details>

## Setting an Application Capability Grant

tsidp requires an [Application capability grant](https://tailscale.com/kb/1537/grants-app-capabilities) to allow access to the admin UI and dynamic client registration endpoints.

This is a permissive grant that is suitable only for testing purposes:

```json
"grants": [
  {
    "src": ["*"],
    "dst": ["*"],
    "app": {
      "tailscale.com/cap/tsidp": [
        {
          // STS controls
          "users":     ["*"],
          "resources": ["*"],

          // allow access to UI
          "allow_admin_ui": true,

          // allow dynamic client registration
          "allow_dcr": true,
        },
      ],
    },
  },
],
```

## Application Configuration Guides

tsidp can be used as IdP server for any application that supports custom OIDC providers.

> [!IMPORTANT]
> Note: If you'd like to use tsidp to login to a SaaS application outside of your tailnet rather than a self-hosted app inside of your tailnet, you'll need to run tsidp with `--funnel` enabled.

- (TODO) Proxmox
- (TODO) Grafana
- (TODO) open-webui
- (TODO) Jellyfin
- (TODO) Salesforce
- (TODO) ...

## MCP Configuration Guides

tsidp supports all of the endpoints required & suggested by the [MCP Authorization specification](https://modelcontextprotocol.io/specification/draft/basic/authorization), including Dynamic Client Registration (DCR). More information can be found in the following examples:

- [MCP Client / Server](./examples/mcp-server/README.md)
- [MCP Client / Gateway Server](./examples/mcp-gateway/README.md)

## tsidp Configuration Options

The `tsidp` server is configured by several command-line flags:

- `-verbose`: Enable verbose logging
- `-port`: Port to listen on (default: 443)
- `-local-port`: Allow requests from localhost
- `-use-local-tailscaled`: Use local tailscaled instead of tsnet
- `-funnel`: Use Tailscale Funnel to make tsidp available on the public internet so it works with SaaS products
- `-hostname`: tsnet hostname
- `-dir`: tsnet state directory
- `-enable-sts`: Enable OAuth token exchange using RFC 8693
- `-enable-debug`: Enable debug printing of requests to the server

### Environment Variables

These are needed while tsidp is in development (< v1.0.0):

- `TAILSCALE_USE_WIP_CODE`: Enable work-in-progress code (default: "1", required)
- `TS_AUTHKEY`: Your Tailscale authentication key (required)

The docker container accepts environment variables that are mapped to the command-line flags:

| Environment Variable            | CLI flag                   |
| ------------------------------- | -------------------------- |
| `TS_HOSTNAME=<hostname>`        | `-hostname <hostname>`     |
| `TS_STATE_DIR=<directory>`      | `-dir <directory>`         |
| `TSIDP_USE_FUNNEL=1`            | `-funnel`                  |
| `TSIDP_PORT=<port>`             | `-port <port>`             |
| `TSIDP_LOCAL_PORT=<local-port>` | `-local-port <local-port>` |
| `TSIDP_ENABLE_STS=1`            | `-enable-sts`              |
| `TSIDP_VERBOSE=1`               | `-verbose`                 |
| `TSIDP_ENABLE_DEBUG=1`          | `-enable-debug`            |

All environment variables are optional. When omitted the default value for the command-line flag will be used.

## Support

This is an experimental, work in progress, [community project](https://tailscale.com/kb/1531/community-projects). For issues or questions, file issues on the [GitHub repository](https://github.com/tailscale/tsidp).

## License

BSD-3-Clause License. See [LICENSE](./LICENSE) for details.
