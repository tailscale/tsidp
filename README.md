# `tsidp` - Tailscale OpenID Connect (OIDC) Identity Provider

[![status: community project](https://img.shields.io/badge/status-community_project-blue)](https://tailscale.com/kb/1531/community-projects)

`tsidp` is an OIDC / OAuth Identity Provider (IdP) server that integrates with your Tailscale network. It allows you to use Tailscale identities for authentication into applications that support OpenID Connect as well as authenticated MCP client / server connections.

## Prerequisites

- A Tailscale network (tailnet) with magicDNS and HTTPS enabled
- A Tailscale authentication key from your tailnet
- (Recommended) Docker installed on your system

## Running tsidp

The easiest way to run tsidp is using a pre-built image.

### (Recommended) Running the tsidp image

TODO

### Running tsidp directly

If you'd like to build tsidp and / or run it directly you can do the following:

```bash
# Clone the Tailscale repository
git clone https://github.com/tailscale/tsidp.git
cd tsidp
```

Replace `YOUR_TAILSCALE_AUTHKEY` with your Tailscale authentication key in the following commands:

1. Use an existing auth key or create a new auth key in the [Tailscale dashboard](https://login.tailscale.com/admin/settings/keys). Ensure you select an existing tag or create a new one.
2. Run `$ TS_AUTH_KEY=YOUR_TAILSCALE_AUTHKEY TAILSCALE_USE_WIP_CODE=1 TSNET_FORCE_LOGIN=1 go run .`

Visit `https://idp.yourtailnet.ts.net` to confirm the service is running.

## Application Configuration Guides

tsidp can be used as IdP server for any application that supports custom OIDC providers.

*Note: If you're running the application(s) inside of your tailnet, you wont need to do anything extra when running tsidp. If you'd like to use tsidp to login to a SaaS application outside of your tailnet, you'll need to run tsidp with `--funnel` enabled.*

 - TODO — Need to add the initial list. Existing proxmox instructions wont work.

## MCP Configuration Guides

tsidp supports all of the endpoints required & suggested by the [MCP Authorization specification](https://modelcontextprotocol.io/specification/draft/basic/authorization), including Dynamic Client Registration (DCR). More information can be found in the following examples:

- (TODO) MCP Client / Server
- (TODO) MCP Client / Gateway Server

## tsidp Configuration Options

The `tsidp` server supports several command-line flags:

- `--verbose`: Enable verbose logging
- `--port`: Port to listen on (default: 443)
- `--local-port`: Allow requests from localhost
- `--use-local-tailscaled`: Use local tailscaled instead of tsnet
- `--funnel`: Use Tailscale Funnel to make tsidp available on the public internet so it works with SaaS products
- `--hostname`: tsnet hostname
- `--dir`: tsnet state directory
- `--enable-sts`: Enable OAuth token exchange using RFC 8693
- `--enable-debug`: Enable debug printing of requests to the server

### Environment Variables

- `TS_AUTHKEY`: Your Tailscale authentication key (required)
- `TS_HOSTNAME`: Hostname for the `tsidp` server (default: "idp", Docker only)
- `TS_STATE_DIR`: State directory (default: "/var/lib/tsidp", Docker only)
- `TAILSCALE_USE_WIP_CODE`: Enable work-in-progress code (default: "1")

## Support

This is an experimental, work in progress, [community project](https://tailscale.com/kb/1531/community-projects). For issues or questions, file issues on the [GitHub repository](https://github.com/tailscale/tsidp).

## License

BSD-3-Clause License. See [LICENSE](./LICENSE) for details.
