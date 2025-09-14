"""MCP Server with OAuth 2.1 authentication."""

import asyncio
import logging
from typing import List, Optional

from mcp.server.fastmcp.server import FastMCP
from mcp.server.auth.settings import AuthSettings
from starlette.requests import Request
from starlette.responses import JSONResponse

# Set up logging
logger = logging.getLogger(__name__)

from .auth import create_token_verifier
from .tools import register_tools
from .discovery import discover_authorization_server, OAuthDiscoveryError
from .registration import register_oauth_client, generate_client_name, ClientRegistrationError, RegisteredClient


async def setup_oauth_client(
    auth_server_url: str,
    server_url: str,
    client_name: Optional[str] = None,
    force_reregister: bool = False,
    debug: bool = False,
) -> RegisteredClient:
    """Setup OAuth client registration and return client credentials.
    
    Args:
        auth_server_url: OAuth authorization server base URL
        server_url: This server's base URL
        client_name: Name for client registration (auto-generated if None)
        force_reregister: Whether to force new registration
        debug: Enable debug logging
        
    Returns:
        Registered client information
        
    Raises:
        OAuthDiscoveryError: If discovery fails
        ClientRegistrationError: If registration fails
    """
    if debug:
        print(f"Discovering OAuth endpoints at {auth_server_url}...")
    
    # Discover authorization server metadata
    try:
        metadata = await discover_authorization_server(auth_server_url)
    except OAuthDiscoveryError as e:
        raise OAuthDiscoveryError(f"Failed to discover OAuth endpoints: {e}")
    
    if debug:
        print(f"Found registration endpoint: {metadata.registration_endpoint}")
        print(f"Found introspection endpoint: {metadata.introspection_endpoint}")
    
    # Generate client name if not provided
    if not client_name:
        client_name = generate_client_name()
    
    if debug:
        print(f"Registering OAuth client '{client_name}'...")
    
    # Register as OAuth client
    try:
        client = await register_oauth_client(
            registration_endpoint=metadata.registration_endpoint,
            client_name=client_name,
            server_url=server_url,
        )
    except ClientRegistrationError as e:
        raise ClientRegistrationError(f"Failed to register OAuth client: {e}")
    
    if debug:
        print(f"Successfully registered as client: {client.client_id}")
    
    return client


def create_server(
    auth_server_url: str,
    host: str = "localhost",
    port: int = 8001,
    debug: bool = False,
    required_scopes: List[str] = None,
    client_name: Optional[str] = None,
    force_reregister: bool = False,
) -> FastMCP:
    """Create and configure the MCP server with OAuth 2.1 authentication.
    
    Args:
        auth_server_url: OAuth authorization server base URL
        host: Server host address
        port: Server port number
        debug: Enable debug mode
        required_scopes: List of required OAuth scopes
        client_name: OAuth client name for registration
        force_reregister: Force new client registration
        
    Returns:
        Configured FastMCP server instance
    """
    if required_scopes is None:
        required_scopes = ["openid"]
    
    # Construct this server's URL
    server_url = f"http://{host}:{port}"
    
    # Setup OAuth client registration synchronously
    try:
        # Run async OAuth setup in event loop
        client = asyncio.run(setup_oauth_client(
            auth_server_url=auth_server_url,
            server_url=server_url,
            client_name=client_name,
            force_reregister=force_reregister,
            debug=debug,
        ))
    except (OAuthDiscoveryError, ClientRegistrationError) as e:
        raise RuntimeError(f"OAuth setup failed: {e}")
    
    # Discover endpoints for token verifier
    try:
        metadata = asyncio.run(discover_authorization_server(auth_server_url))
    except OAuthDiscoveryError as e:
        raise RuntimeError(f"Failed to discover OAuth endpoints: {e}")
    
    # Create token verifier with client authentication
    token_verifier = create_token_verifier(
        introspection_endpoint=metadata.introspection_endpoint,
        server_url=server_url,
        client_id=client.client_id,
        client_secret=client.client_secret,
        validate_resource=True,
    )
    
    if debug:
        # Configure detailed logging for debugging
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        # Set specific loggers to appropriate levels
        logging.getLogger('mcp_auth_server.auth').setLevel(logging.DEBUG)
        logging.getLogger('mcp.server.auth').setLevel(logging.DEBUG)
        logging.getLogger('httpx').setLevel(logging.INFO)
        print(f"Token verifier configured with client ID: {client.client_id}")
        print(f"Debug logging enabled for authentication components")
    else:
        # Configure basic logging for production
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        logging.getLogger('mcp_auth_server.auth').setLevel(logging.INFO)
    
    logger.info(f"Creating MCP server with required scopes: {required_scopes}")
    logger.info(f"Token verifier endpoint: {metadata.introspection_endpoint}")
    logger.info(f"Resource server URL: {server_url}")
    
    # Create FastMCP server as OAuth Resource Server
    app = FastMCP(
        name=f"MCP OAuth Resource Server ({client.client_name})",
        instructions=(
            "This is an MCP server that provides authenticated tools. "
            "All tools require valid OAuth 2.1 Bearer tokens with appropriate scopes. "
            f"Server registered as OAuth client: {client.client_id}. "
            "Available tools: multiply (multiply two numbers), oauth_details (get token info)."
        ),
        host=host,
        port=port,
        debug=debug,
        # Authentication configuration
        token_verifier=token_verifier,
        auth=AuthSettings(
            issuer_url=auth_server_url,
            required_scopes=required_scopes,
            resource_server_url=server_url,
        ),
    )
    
    # Register protected tools
    register_tools(app)
    
    # Add OAuth Authorization Server discovery endpoint
    # This tells clients where to find the actual authorization server
    @app.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
    async def oauth_authorization_server_metadata(request: Request) -> JSONResponse:
        """OAuth 2.0 Authorization Server Metadata (RFC 8414)."""
        logger.info(f"OAuth authorization server metadata requested from {request.client.host if request.client else 'unknown'}")
        # Return the authorization server's metadata (proxy to actual server)
        return JSONResponse(metadata.raw_metadata)
    
    # Add OAuth discovery endpoint (RFC 8414 Protected Resource Metadata)
    @app.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
    async def oauth_protected_resource_metadata(request: Request) -> JSONResponse:
        """OAuth 2.0 Protected Resource Metadata (RFC 8414)."""
        logger.info(f"OAuth protected resource metadata requested from {request.client.host if request.client else 'unknown'}")
        resource_metadata = {
            "resource": server_url,
            "authorization_servers": [auth_server_url],
            "scopes_supported": required_scopes,
            "bearer_methods_supported": ["header"],
            "resource_documentation": "https://modelcontextprotocol.io/",
            "client_id": client.client_id,  # Include our client ID for reference
        }
        logger.debug(f"Returning resource metadata: {resource_metadata}")
        return JSONResponse(resource_metadata)
    
    # Add client info endpoint for debugging
    @app.custom_route("/oauth/client-info", methods=["GET"])
    async def client_info(request: Request) -> JSONResponse:
        """Return OAuth client registration information."""
        return JSONResponse(client.to_dict())
    
    if debug:
        print(f"MCP server created successfully with OAuth client: {client.client_id}")
    
    logger.info(f"MCP server ready - OAuth client: {client.client_id}")
    logger.info(f"Server will require scopes: {required_scopes}")
    logger.info(f"Discovery endpoints available at {server_url}/.well-known/")
    
    return app