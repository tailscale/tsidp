#!/usr/bin/env python3
"""MCP Gateway with RFC 8693 OAuth Token Exchange support."""

import asyncio
import logging
from typing import Optional

import click
import structlog
from rich.console import Console
from rich.logging import RichHandler

from .gateway import GatewayServer
from .logging import setup_logging

console = Console()
logger = structlog.get_logger(__name__)


@click.command()
@click.option(
    "--auth-server-url",
    required=True,
    help="OAuth authorization server URL (e.g., https://idp-10.tailfeb87.ts.net/)",
)
@click.option(
    "--mcp-server-url",
    required=True,
    help="MCP server URL to proxy to (e.g., http://localhost:8002)",
)
@click.option(
    "--host",
    default="localhost",
    help="Host to bind the gateway to (default: localhost)",
)
@click.option(
    "--port",
    default=8003,
    type=int,
    help="Port to bind the gateway to (default: 8003)",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable detailed debug logging of all requests and responses",
)
@click.option(
    "--client-id",
    help="OAuth client ID for token exchange (optional)",
)
@click.option(
    "--client-secret",
    help="OAuth client secret for token exchange (optional)",
)
def cli(
    auth_server_url: str,
    mcp_server_url: str,
    host: str,
    port: int,
    debug: bool,
    client_id: Optional[str],
    client_secret: Optional[str],
):
    """MCP Gateway with RFC 8693 OAuth Token Exchange support.
    
    This gateway acts as a transparent proxy between MCP clients and servers,
    handling OAuth 2.0 token exchange as specified in RFC 8693.
    
    The gateway:
    - Proxies MCP protocol messages between client and server
    - Intercepts authentication requests for token exchange
    - Supports streamable-http transport (not SSE)
    - Provides detailed debug logging when enabled
    
    Example:
        uv run mcp-auth-gateway \\
            --auth-server-url https://idp-10.tailfeb87.ts.net/ \\
            --mcp-server-url http://localhost:8002 \\
            --debug
    """
    # Setup logging
    setup_logging(debug=debug)
    
    # Print startup banner
    console.print(f"[bold green]MCP Auth Gateway v0.1.0[/bold green]")
    console.print(f"[blue]Authorization Server:[/blue] {auth_server_url}")
    console.print(f"[blue]MCP Server:[/blue] {mcp_server_url}")
    console.print(f"[blue]Gateway URL:[/blue] http://{host}:{port}")
    if debug:
        console.print("[yellow]Debug mode enabled - detailed logging active[/yellow]")
    console.print()
    
    # Create and run the gateway server
    gateway = GatewayServer(
        auth_server_url=auth_server_url,
        mcp_server_url=mcp_server_url,
        host=host,
        port=port,
        debug=debug,
        client_id=client_id,
        client_secret=client_secret,
    )
    
    try:
        # Run the gateway
        asyncio.run(gateway.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Gateway shutting down...[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback
            traceback.print_exc()
        raise


if __name__ == "__main__":
    cli()