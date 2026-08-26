#!/usr/bin/env python3
"""
MCP OAuth Client CLI

A command-line interface for interacting with MCP servers using OAuth2.1 authentication.
"""

import asyncio
import json
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import click
from mcp.client.auth import OAuthClientProvider
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.auth import OAuthClientMetadata
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.json import JSON
from rich.panel import Panel
from rich.syntax import Syntax
from rich.logging import RichHandler

from .auth import handle_oauth_callback, open_browser
from .storage import FileTokenStorage

console = Console()

# Configure logging
logger = logging.getLogger("mcp_oauth_client")


class LoggingOAuthProvider(OAuthClientProvider):
    """OAuth provider with detailed logging for debugging token refresh issues."""
    
    def __init__(self, *args, enable_debug: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.enable_debug = enable_debug
        self._request_counter = 0
        
        # Log the initial client metadata including scope
        if self.enable_debug and hasattr(self, 'client_metadata'):
            logger.info(f"[INIT] Client metadata - scope: {self.client_metadata.scope}")
            logger.info(f"[INIT] Client metadata - grant types: {self.client_metadata.grant_types}")
    
    def _add_auth_header(self, request):
        """Override to add logging when auth headers are set."""
        if self.enable_debug and self.context.current_tokens and self.context.current_tokens.access_token:
            token = self.context.current_tokens.access_token
            token_preview = f"{token[:8]}...{token[-8:]}" if len(token) > 16 else "[short token]"
            logger.info(f"[AUTH] Setting Authorization header with token: {token_preview}")
            logger.info(f"[AUTH] Token expiry time: {self.context.token_expiry_time}")
            logger.info(f"[AUTH] Current time: {datetime.now()}")
            # Check if token is expired
            is_valid = True
            if self.context.token_expiry_time:
                # Convert Unix timestamp to datetime for comparison
                expiry_datetime = datetime.fromtimestamp(self.context.token_expiry_time)
                is_valid = datetime.now() < expiry_datetime
            logger.info(f"[AUTH] Token valid: {is_valid}")
        super()._add_auth_header(request)
    
    async def async_auth_flow(self, request):
        """Override to add detailed logging of auth flow."""
        self._request_counter += 1
        request_id = self._request_counter
        
        if self.enable_debug:
            logger.info(f"[REQUEST {request_id}] Starting auth flow for {request.method} {request.url}")
            logger.info(f"[REQUEST {request_id}] Headers before auth: {dict(request.headers)}")
            
            # Log server metadata if available
            if hasattr(self, 'server_metadata') and self.server_metadata:
                if hasattr(self.server_metadata, 'scopes_supported'):
                    logger.info(f"[REQUEST {request_id}] Server supported scopes: {self.server_metadata.scopes_supported}")
                if hasattr(self.server_metadata, 'scope'):
                    logger.info(f"[REQUEST {request_id}] Server default scope: {self.server_metadata.scope}")
        
        # Create the parent generator
        parent_gen = super().async_auth_flow(request)
        auth_request = await parent_gen.asend(None)  # Start the generator
        
        while True:
            try:
                if self.enable_debug:
                    logger.info(f"[REQUEST {request_id}] Yielding request with headers: {dict(auth_request.headers)}")
                
                # Yield the request and get the response
                response = yield auth_request
                
                if self.enable_debug and response:
                    logger.info(f"[REQUEST {request_id}] Got response: {response.status_code}")
                    if response.status_code == 401:
                        logger.warning(f"[REQUEST {request_id}] Got 401 Unauthorized - will attempt token refresh")
                
                # Send the response back to the parent generator
                auth_request = await parent_gen.asend(response)
                
            except StopAsyncIteration:
                # Parent generator is done
                break
    
    async def _refresh_token(self):
        """Override to add logging for token refresh."""
        if self.enable_debug:
            old_token = self.context.current_tokens.access_token if self.context.current_tokens else None
            old_preview = f"{old_token[:8]}...{old_token[-8:]}" if old_token and len(old_token) > 16 else "[no token]"
            logger.info(f"[REFRESH] Starting token refresh. Old token: {old_preview}")
        
        result = await super()._refresh_token()
        
        if self.enable_debug:
            if result:
                # Get new token from result if available, otherwise from context
                new_token = result.access_token if hasattr(result, 'access_token') else (
                    self.context.current_tokens.access_token if self.context.current_tokens else None
                )
                new_preview = f"{new_token[:8]}...{new_token[-8:]}" if new_token and len(new_token) > 16 else "[no token]"
                logger.info(f"[REFRESH] Token refresh successful. New token: {new_preview}")
                logger.info(f"[REFRESH] New expiry time: {self.context.token_expiry_time}")
                
                # Log the scope if available in the token response
                if self.context.current_tokens and hasattr(self.context.current_tokens, 'scope'):
                    logger.info(f"[REFRESH] Granted scope: {self.context.current_tokens.scope}")
            else:
                logger.error("[REFRESH] Token refresh failed")
        
        return result
    
    async def _exchange_code_for_token(self, code: str, code_verifier: Optional[str] = None):
        """Override to add logging for initial token exchange."""
        if self.enable_debug:
            logger.info(f"[TOKEN_EXCHANGE] Exchanging authorization code for tokens")
        
        result = await super()._exchange_code_for_token(code, code_verifier)
        
        if self.enable_debug and result:
            logger.info(f"[TOKEN_EXCHANGE] Token exchange successful")
            if hasattr(result, 'scope'):
                logger.info(f"[TOKEN_EXCHANGE] Granted scope: {result.scope}")
            elif self.context.current_tokens and hasattr(self.context.current_tokens, 'scope'):
                logger.info(f"[TOKEN_EXCHANGE] Granted scope: {self.context.current_tokens.scope}")
            else:
                logger.info(f"[TOKEN_EXCHANGE] No scope found in token response")
            
            # Log all available attributes for debugging
            if hasattr(result, '__dict__'):
                logger.info(f"[TOKEN_EXCHANGE] Token response attributes: {list(result.__dict__.keys())}")
        
        return result


class MCPClient:
    """MCP client with OAuth authentication support."""
    
    def __init__(self, server_url: str, callback_port: int = 3000, debug_logging: bool = False):
        """Initialize MCP client with server URL."""
        self.server_url = server_url
        self.callback_port = callback_port
        self.session: Optional[ClientSession] = None
        self.session_id: Optional[str] = None
        self.storage = FileTokenStorage(server_url=server_url)
        self.debug_logging = debug_logging
        self._request_counter = 0
    
    async def __aenter__(self):
        """Enter the context manager and connect."""
        await self._connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit the context manager."""
        # Cleanup is handled by the context managers in _connect
        pass
    
    async def _connect(self):
        """Connect to the MCP server with OAuth authentication."""
        console.print(f"[blue]Connecting to MCP server: {self.server_url}[/blue]")
        
        try:
            # OAuth client metadata
            client_metadata = OAuthClientMetadata(
                client_name="MCP OAuth CLI Client",
                redirect_uris=[f"http://localhost:{self.callback_port}/callback"],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                token_endpoint_auth_method="client_secret_post",
                scope="openid profile email"  # Request required scopes including openid
            )
            
            # Log initial client metadata
            if self.debug_logging:
                logger.info(f"[CLIENT_INIT] Initial client metadata:")
                logger.info(f"[CLIENT_INIT] - client_name: {client_metadata.client_name}")
                logger.info(f"[CLIENT_INIT] - grant_types: {client_metadata.grant_types}")
                logger.info(f"[CLIENT_INIT] - scope: {client_metadata.scope} (will be set from server metadata)")
            
            # Create OAuth provider with optional debug logging
            oauth_provider = LoggingOAuthProvider(
                server_url=self.server_url.replace("/mcp", ""),
                client_metadata=client_metadata,
                storage=self.storage,
                redirect_handler=open_browser,
                callback_handler=lambda: handle_oauth_callback(self.callback_port),
                timeout=300.0,
                enable_debug=self.debug_logging
            )
            
            # Store these for later use
            self._oauth_provider = oauth_provider
            
            # Connect using streamable HTTP transport
            self._transport_cm = streamablehttp_client(
                url=self.server_url,
                auth=oauth_provider,
                timeout=timedelta(seconds=30),
                sse_read_timeout=timedelta(minutes=5)
            )
            
            read_stream, write_stream, get_session_id = await self._transport_cm.__aenter__()
            console.print("[green]✓ Connected to MCP server[/green]")
            
            # Initialize session
            self._session_cm = ClientSession(read_stream, write_stream)
            self.session = await self._session_cm.__aenter__()
            await self.session.initialize()
            
            # Get session ID
            self.session_id = get_session_id()
            if self.session_id:
                console.print(f"[dim]Session ID: {self.session_id}[/dim]")
            
            console.print("[green]✓ Session initialized[/green]")
                    
        except Exception as e:
            console.print(f"[red]✗ Connection failed: {e}[/red]")
            # Clean up if initialization failed
            if hasattr(self, '_session_cm'):
                await self._session_cm.__aexit__(None, None, None)
            if hasattr(self, '_transport_cm'):
                await self._transport_cm.__aexit__(None, None, None)
            raise
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit the context manager and clean up."""
        # Clean up in reverse order
        if hasattr(self, '_session_cm'):
            await self._session_cm.__aexit__(exc_type, exc_val, exc_tb)
        if hasattr(self, '_transport_cm'):
            await self._transport_cm.__aexit__(exc_type, exc_val, exc_tb)
    
    async def list_tools(self) -> list[Dict[str, Any]]:
        """List available tools from the server."""
        if not self.session:
            raise RuntimeError("Not connected to server")
        
        result = await self.session.list_tools()
        return [tool.model_dump() for tool in result.tools] if result.tools else []
    
    async def call_tool(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        """Call a specific tool with arguments."""
        if not self.session:
            raise RuntimeError("Not connected to server")
        
        result = await self.session.call_tool(tool_name, arguments or {})
        return result


@click.group(invoke_without_command=True)
@click.argument('server_url', required=False)
@click.option('--port', default=3000, help='OAuth callback port (default: 3000)')
@click.option('--debug', is_flag=True, help='Enable detailed debug logging for OAuth flow')
@click.pass_context
def cli(ctx, server_url: Optional[str], port: int, debug: bool):
    """MCP OAuth Client - Interact with MCP servers using OAuth2.1 authentication.
    
    When called with just a SERVER_URL, starts interactive mode.
    """
    ctx.ensure_object(dict)
    ctx.obj['debug'] = debug
    
    # Configure logging if debug is enabled
    if debug:
        logging.basicConfig(
            level=logging.INFO,
            format="%(message)s",
            handlers=[
                RichHandler(console=console, show_time=True, show_path=False)
            ]
        )
        # Also enable debug logging for the MCP library
        logging.getLogger("mcp").setLevel(logging.DEBUG)
    
    # If server_url is provided and no subcommand, run interactive mode
    if ctx.invoked_subcommand is None:
        if server_url:
            # Default to interactive mode
            asyncio.run(run_interactive(server_url, port, debug))
        else:
            # Show help if no server URL provided
            click.echo(ctx.get_help())


async def run_interactive(server_url: str, port: int, debug: bool = False):
    """Run interactive mode - extracted for reuse."""
    client = MCPClient(server_url, callback_port=port, debug_logging=debug)
    async with client as connected_client:
        console.print(Panel.fit(
            "[bold green]Interactive MCP Client[/bold green]\n"
            "Commands: list, call <tool> [args], help, quit",
            border_style="green"
        ))
        
        while True:
            try:
                command = Prompt.ask("\n[bold blue]mcp>[/bold blue]").strip()
                
                if not command:
                    continue
                
                if command == "quit" or command == "exit":
                    console.print("[yellow]Goodbye![/yellow]")
                    break
                
                elif command == "help":
                    console.print(Panel(
                        "[bold]Available commands:[/bold]\n\n"
                        "• [cyan]list[/cyan] - List available tools\n"
                        "• [cyan]call <tool> [args][/cyan] - Call a tool with optional JSON args\n"
                        "• [cyan]help[/cyan] - Show this help message\n"
                        "• [cyan]quit[/cyan] - Exit the interactive session\n\n"
                        "Example: [dim]call get_weather {\"location\": \"London\"}[/dim]",
                        title="Help",
                        border_style="blue"
                    ))
                
                elif command == "list":
                    tools = await connected_client.list_tools()
                    
                    if not tools:
                        console.print("[yellow]No tools available[/yellow]")
                        continue
                    
                    table = Table(show_header=True, header_style="bold blue")
                    table.add_column("Tool", style="cyan")
                    table.add_column("Description", style="white")
                    
                    for tool in tools:
                        table.add_row(
                            tool['name'],
                            tool.get('description', 'No description')
                        )
                    
                    console.print(table)
                
                elif command.startswith("call "):
                    parts = command.split(maxsplit=2)
                    if len(parts) < 2:
                        console.print("[red]Usage: call <tool_name> [json_args][/red]")
                        continue
                    
                    tool_name = parts[1]
                    arguments = {}
                    
                    if len(parts) > 2:
                        try:
                            arguments = json.loads(parts[2])
                        except json.JSONDecodeError:
                            console.print("[red]Invalid JSON arguments[/red]")
                            continue
                    
                    try:
                        result = await connected_client.call_tool(tool_name, arguments)
                        
                        if hasattr(result, 'content'):
                            for content in result.content:
                                if content.type == 'text':
                                    console.print(content.text)
                                else:
                                    console.print(JSON.from_data(content.model_dump()))
                        else:
                            console.print(result)
                            
                    except Exception as e:
                        console.print(f"[red]Error: {e}[/red]")
                
                else:
                    console.print(f"[red]Unknown command: {command}[/red]")
                    console.print("[dim]Type 'help' for available commands[/dim]")
            
            except KeyboardInterrupt:
                console.print("\n[yellow]Use 'quit' to exit[/yellow]")
            except EOFError:
                console.print("\n[yellow]Goodbye![/yellow]")
                break


@cli.command()
@click.argument('server_url')
@click.option('--port', default=3000, help='OAuth callback port (default: 3000)')
@click.pass_context
def list_tools(ctx, server_url: str, port: int):
    """List available tools from an MCP server."""
    debug = ctx.obj.get('debug', False)
    async def run():
        client = MCPClient(server_url, callback_port=port, debug_logging=debug)
        async with client as connected_client:
            tools = await connected_client.list_tools()
            
            if not tools:
                console.print("[yellow]No tools available on this server[/yellow]")
                return
            
            # Create table for tools
            table = Table(title="Available Tools", show_header=True, header_style="bold blue")
            table.add_column("Name", style="cyan", no_wrap=True)
            table.add_column("Description", style="white")
            table.add_column("Parameters", style="green")
            
            for tool in tools:
                params_str = ""
                if tool.get('inputSchema', {}).get('properties'):
                    params = list(tool['inputSchema']['properties'].keys())
                    params_str = ", ".join(params)
                
                table.add_row(
                    tool['name'],
                    tool.get('description', 'No description'),
                    params_str
                )
            
            console.print(table)
    
    asyncio.run(run())


@cli.command()
@click.argument('server_url')
@click.argument('tool_name')
@click.option('--args', '-a', help='Tool arguments as JSON string')
@click.option('--port', default=3000, help='OAuth callback port (default: 3000)')
@click.pass_context
def call_tool(ctx, server_url: str, tool_name: str, args: Optional[str], port: int):
    """Call a specific tool on an MCP server."""
    debug = ctx.obj.get('debug', False)
    async def run():
        # Parse arguments if provided
        arguments = {}
        if args:
            try:
                arguments = json.loads(args)
            except json.JSONDecodeError as e:
                console.print(f"[red]Invalid JSON arguments: {e}[/red]")
                return
        
        client = MCPClient(server_url, callback_port=port, debug_logging=debug)
        async with client as connected_client:
            console.print(f"[blue]Calling tool: {tool_name}[/blue]")
            if arguments:
                console.print(Panel(JSON.from_data(arguments), title="Arguments", border_style="dim"))
            
            try:
                result = await connected_client.call_tool(tool_name, arguments)
                
                # Display result
                console.print(Panel.fit(
                    f"[green]✓ Tool executed successfully[/green]",
                    border_style="green"
                ))
                
                if hasattr(result, 'content'):
                    for content in result.content:
                        if content.type == 'text':
                            console.print(content.text)
                        else:
                            console.print(JSON.from_data(content.model_dump()))
                else:
                    console.print(JSON.from_data(result))
                    
            except Exception as e:
                console.print(f"[red]✗ Tool execution failed: {e}[/red]")
    
    asyncio.run(run())


@cli.command()
@click.argument('server_url')
@click.option('--port', default=3000, help='OAuth callback port (default: 3000)')
@click.pass_context
def interactive(ctx, server_url: str, port: int):
    """Start an interactive session with an MCP server."""
    debug = ctx.obj.get('debug', False)
    asyncio.run(run_interactive(server_url, port, debug))


@cli.command()
@click.argument('server_url', required=False)
@click.pass_context
def clear_auth(ctx, server_url: Optional[str]):
    """Clear stored OAuth tokens and client information.

    If SERVER_URL is provided, only clears data for that server.
    Otherwise, clears all cached OAuth data.
    """
    # Get storage directory
    storage_dir = Path(__file__).parent.parent / '.oauth-cache'

    if server_url:
        # Clear only for specific server
        storage = FileTokenStorage(server_url=server_url)
        storage.clear_all()
        console.print(f"[green]✓ Cleared authentication data for {server_url}[/green]")
    elif storage_dir.exists():
        # Clear all cached data
        import shutil
        shutil.rmtree(storage_dir)
        console.print("[green]✓ Cleared all stored authentication data[/green]")
    else:
        console.print("[yellow]No authentication data to clear[/yellow]")


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
