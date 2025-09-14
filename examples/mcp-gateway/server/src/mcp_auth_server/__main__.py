"""CLI entry point for MCP Auth Server."""

import asyncio
import sys
from typing import Optional

import click
import uvicorn

from .server import create_server


@click.command()
@click.option(
    "--auth-server-url",
    required=True,
    help="OAuth 2.1 authorization server base URL (e.g., http://localhost:9000)",
)
@click.option(
    "--host",
    default="localhost",
    help="Server host address",
)
@click.option(
    "--port",
    default=8001,
    type=int,
    help="Server port number",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable debug mode with verbose logging",
)
@click.option(
    "--required-scopes",
    default="openid",
    help="Comma-separated list of required OAuth scopes",
)
@click.option(
    "--client-name",
    help="OAuth client name for registration (auto-generated if not provided)",
)
@click.option(
    "--force-reregister",
    is_flag=True,
    help="Force new OAuth client registration even if existing credentials work",
)
def main(
    auth_server_url: str,
    host: str,
    port: int,
    debug: bool,
    required_scopes: str,
    client_name: Optional[str],
    force_reregister: bool,
) -> None:
    """Start the MCP Auth Server with OAuth 2.1 authentication.
    
    This server automatically registers itself as an OAuth client with the
    authorization server and uses client credentials to authenticate when
    calling the token introspection endpoint.
    
    This server provides two authenticated tools:
    - multiply: Multiplies two numbers
    - oauth_details: Returns OAuth client information
    
    The server requires valid OAuth 2.1 tokens from the specified authorization server.
    """
    scopes = [scope.strip() for scope in required_scopes.split(",")]
    
    try:
        server = create_server(
            auth_server_url=auth_server_url,
            host=host,
            port=port,
            debug=debug,
            required_scopes=scopes,
            client_name=client_name,
            force_reregister=force_reregister,
        )
        
        if debug:
            click.echo(f"Starting MCP Auth Server on {host}:{port}")
            click.echo(f"Auth Server URL: {auth_server_url}")
            click.echo(f"Required Scopes: {scopes}")
            if client_name:
                click.echo(f"Client Name: {client_name}")
            if force_reregister:
                click.echo("Force re-registration: enabled")
        
        # Run the server
        server.run(transport="streamable-http")
        
    except KeyboardInterrupt:
        if debug:
            click.echo("\nShutting down server...")
        sys.exit(0)
    except RuntimeError as e:
        # OAuth setup errors
        click.echo(f"OAuth setup failed: {e}", err=True)
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error starting server: {e}", err=True)
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()