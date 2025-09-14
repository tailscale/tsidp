"""MCP Gateway Server with OAuth Token Exchange support."""

import asyncio
import json
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager

import httpx
import structlog
import uvicorn
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route

from .token_exchange import TokenExchangeHandler, TokenExchangeError
from .logging import RequestLogger
from .auth_interceptor import AuthInterceptor
from .oauth_registration import (
    discover_oauth_metadata,
    register_oauth_client,
    generate_client_name,
)

logger = structlog.get_logger(__name__)


class GatewayServer:
    """MCP Gateway Server that proxies requests with token exchange support."""
    
    def __init__(
        self,
        auth_server_url: str,
        mcp_server_url: str,
        host: str = "localhost",
        port: int = 8003,
        debug: bool = False,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ):
        """Initialize the gateway server.
        
        Args:
            auth_server_url: OAuth authorization server URL
            mcp_server_url: Target MCP server URL
            host: Host to bind to
            port: Port to bind to
            debug: Enable debug logging
            client_id: OAuth client ID for token exchange
            client_secret: OAuth client secret for token exchange
        """
        self.auth_server_url = auth_server_url.rstrip("/")
        self.mcp_server_url = mcp_server_url.rstrip("/")
        self.host = host
        self.port = port
        self.debug = debug
        self.client_id = client_id
        self.client_secret = client_secret
        
        # Initialize components
        self.request_logger = RequestLogger(debug=debug)
        self.token_handler: Optional[TokenExchangeHandler] = None
        self.auth_interceptor: Optional[AuthInterceptor] = None
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        
        # Statistics tracking
        self.token_exchanges = 0
        self.exchange_failures = 0
        
        # Create Starlette app
        self.app = self._create_app()
    
    async def _initialize_token_handler(self):
        """Initialize the token exchange handler by discovering endpoints and registering as a client."""
        logger.info(
            "token_handler_initialization_starting",
            auth_server_url=self.auth_server_url,
            has_client_id=bool(self.client_id),
            has_client_secret=bool(self.client_secret),
        )
        
        try:
            # Discover OAuth metadata
            logger.info("attempting_oauth_metadata_discovery", auth_server_url=self.auth_server_url)
            
            try:
                metadata = await discover_oauth_metadata(self.auth_server_url)
                
                logger.info(
                    "oauth_metadata_discovery_successful",
                    issuer=metadata.issuer,
                    token_endpoint=metadata.token_endpoint,
                    registration_endpoint=metadata.registration_endpoint,
                    introspection_endpoint=metadata.introspection_endpoint,
                    jwks_uri=metadata.jwks_uri,
                    scopes_supported=metadata.scopes_supported,
                    response_types_supported=metadata.response_types_supported,
                    grant_types_supported=metadata.grant_types_supported,
                    token_endpoint_auth_methods_supported=metadata.token_endpoint_auth_methods_supported,
                )
                
            except Exception as discovery_error:
                logger.error(
                    "oauth_metadata_discovery_failed",
                    auth_server_url=self.auth_server_url,
                    error=str(discovery_error),
                    error_type=type(discovery_error).__name__,
                )
                raise discovery_error
            
            # Check if token exchange grant type is supported
            if metadata.grant_types_supported:
                token_exchange_supported = "urn:ietf:params:oauth:grant-type:token-exchange" in metadata.grant_types_supported
                logger.info(
                    "token_exchange_grant_type_check",
                    supported_grant_types=metadata.grant_types_supported,
                    token_exchange_supported=token_exchange_supported,
                )
            else:
                logger.warning("no_grant_types_in_metadata", message="IDP did not specify supported grant types")
            
            # Decide on client credentials approach
            if not self.client_id or not self.client_secret:
                logger.info(
                    "client_credentials_not_provided",
                    message="No client credentials provided, attempting dynamic registration",
                    has_registration_endpoint=bool(metadata.registration_endpoint),
                )
                
                if metadata.registration_endpoint:
                    logger.info("attempting_dynamic_client_registration")
                    
                    try:
                        # Generate gateway URL
                        gateway_url = f"http://{self.host}:{self.port}"
                        
                        # Register the gateway as an OAuth client
                        client_name = generate_client_name()
                        logger.info(
                            "registering_gateway_as_oauth_client",
                            registration_endpoint=metadata.registration_endpoint,
                            client_name=client_name,
                            gateway_url=gateway_url,
                        )
                        
                        registered_client = await register_oauth_client(
                            registration_endpoint=metadata.registration_endpoint,
                            client_name=client_name,
                            gateway_url=gateway_url,
                        )
                        
                        # Use the registered credentials
                        self.client_id = registered_client.client_id
                        self.client_secret = registered_client.client_secret
                        
                        logger.info(
                            "gateway_registered_as_oauth_client",
                            client_id=self.client_id,
                            client_name=registered_client.client_name or "Not provided by IDP",
                            token_endpoint_auth_method=registered_client.token_endpoint_auth_method,
                            grant_types=registered_client.grant_types,
                            scope=registered_client.scope,
                        )
                        
                    except Exception as registration_error:
                        logger.error(
                            "dynamic_client_registration_failed",
                            registration_endpoint=metadata.registration_endpoint,
                            error=str(registration_error),
                            error_type=type(registration_error).__name__,
                        )
                        raise registration_error
                        
                else:
                    logger.warning(
                        "no_registration_endpoint",
                        message="No dynamic registration endpoint found and no client credentials provided",
                    )
                    logger.error("token_handler_initialization_impossible", message="Cannot proceed without client credentials")
                    self.token_handler = None
                    return
            else:
                logger.info(
                    "using_provided_client_credentials",
                    client_id=self.client_id,
                    has_client_secret=bool(self.client_secret),
                )
            
            # Validate we have what we need
            if not self.client_id or not self.client_secret:
                logger.error(
                    "missing_client_credentials_after_init",
                    has_client_id=bool(self.client_id),
                    has_client_secret=bool(self.client_secret),
                )
                self.token_handler = None
                return
            
            # Create token handler with discovered endpoint and credentials
            logger.info(
                "creating_token_handler",
                token_endpoint=metadata.token_endpoint,
                client_id=self.client_id,
                has_client_secret=bool(self.client_secret),
                debug=self.debug,
            )
            
            try:
                self.token_handler = TokenExchangeHandler(
                    token_endpoint=metadata.token_endpoint,
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                    debug=self.debug,
                )
                
                logger.info(
                    "token_handler_initialized_successfully",
                    token_endpoint=metadata.token_endpoint,
                    has_client_credentials=bool(self.client_id and self.client_secret),
                )
                
            except Exception as handler_creation_error:
                logger.error(
                    "token_handler_creation_failed",
                    error=str(handler_creation_error),
                    error_type=type(handler_creation_error).__name__,
                )
                raise handler_creation_error
            
        except Exception as e:
            logger.error(
                "token_handler_initialization_failed",
                error=str(e),
                error_type=type(e).__name__,
                message="Token exchange will not be available",
            )
            if self.debug:
                import traceback
                logger.error(
                    "token_handler_initialization_stacktrace",
                    stacktrace=traceback.format_exc(),
                )
            self.token_handler = None
    
    @asynccontextmanager
    async def lifespan(self, app):
        """Manage the application lifecycle."""
        # Startup
        logger.info("gateway_starting", auth_server=self.auth_server_url, mcp_server=self.mcp_server_url)
        
        # Initialize token handler
        await self._initialize_token_handler()
        
        # Initialize auth interceptor
        self.auth_interceptor = AuthInterceptor(
            token_handler=self.token_handler,
            mcp_server_url=self.mcp_server_url,
            debug=self.debug,
            gateway_server=self,  # Pass reference for statistics
        )
        
        yield
        
        # Shutdown
        logger.info(
            "gateway_shutting_down",
            stats={
                "token_exchanges": self.token_exchanges,
                "exchange_failures": self.exchange_failures,
            }
        )
        if self.token_handler:
            await self.token_handler.close()
        await self.client.aclose()
    
    def _create_app(self) -> Starlette:
        """Create the Starlette application."""
        # Define routes
        routes = [
            # MCP streamable-http endpoint
            Route("/mcp", self.handle_mcp_request, methods=["POST", "GET"]),
            # OAuth discovery endpoints (proxy from auth server)
            Route("/.well-known/oauth-authorization-server", self.proxy_oauth_metadata),
            Route("/.well-known/openid-configuration", self.proxy_openid_config),
            # Health check
            Route("/health", self.health_check),
            # Catch-all proxy
            Route("/{path:path}", self.proxy_request, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]),
        ]
        
        # Middleware
        middleware = [
            Middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_methods=["*"],
                allow_headers=["*"],
            ),
        ]
        
        return Starlette(
            routes=routes,
            middleware=middleware,
            lifespan=self.lifespan,
            debug=self.debug,
        )
    
    async def handle_mcp_request(self, request: Request) -> Response:
        """Handle MCP protocol requests with streamable-http transport.
        
        This is the main endpoint for MCP communication. It:
        1. Intercepts authentication headers for token exchange
        2. Proxies the request to the MCP server
        3. Streams the response back to the client
        
        Supports both POST (for initial connection) and GET (for SSE stream).
        """
        # Log incoming request
        if self.debug:
            body = await request.body() if request.method == "POST" else b""
            self.request_logger.log_request(
                method=request.method,
                url=str(request.url),
                headers=dict(request.headers),
                body=body.decode("utf-8") if body else None,
            )
            # Reset body stream for processing
            if body:
                request._body = body
        
        # Process authentication if present
        headers = dict(request.headers)
        if self.auth_interceptor and "authorization" in headers:
            # Intercept and potentially exchange the token
            new_headers = await self.auth_interceptor.process_auth_header(headers)
            if new_headers:
                headers = new_headers
        
        # Remove host header to avoid conflicts
        headers.pop("host", None)
        
        # Get request body (only for POST requests)
        body = await request.body() if request.method == "POST" else b""
        
        # Proxy to MCP server
        target_url = f"{self.mcp_server_url}/mcp"
        
        try:
            # Create a single streaming connection
            async with self.client.stream(
                request.method,
                target_url,
                headers=headers,
                content=body if request.method == "POST" else None,
            ) as response:
                # Log the response
                if self.debug:
                    self.request_logger.log_response(
                        request_id=0,
                        status=response.status_code,
                        headers=dict(response.headers),
                    )
                
                # Store response metadata
                status_code = response.status_code
                response_headers = dict(response.headers)
                content_type = response.headers.get("content-type", "")
                
                # Handle error responses
                if status_code >= 400:
                    error_body = await response.aread()
                    return Response(
                        content=error_body,
                        status_code=status_code,
                        headers=response_headers,
                        media_type=content_type or "application/json",
                    )
                
                # Handle SSE responses - need a new connection with its own lifecycle
                if "text/event-stream" in content_type:
                    # For SSE, we need a generator that owns its connection lifecycle
                    # to prevent the stream from closing prematurely
                    async def stream_sse():
                        # Open a new connection for streaming
                        async with self.client.stream(
                            request.method,
                            target_url,
                            headers=headers,
                            content=body if request.method == "POST" else None,
                        ) as sse_response:
                            # Stream the response
                            async for chunk in sse_response.aiter_bytes():
                                yield chunk
                    
                    return StreamingResponse(
                        stream_sse(),
                        status_code=status_code,
                        headers=response_headers,
                        media_type=content_type,
                    )
                else:
                    # Handle regular responses
                    body_content = await response.aread()
                    return Response(
                        content=body_content,
                        status_code=status_code,
                        headers=response_headers,
                        media_type=content_type or "application/octet-stream",
                    )
                
        except httpx.RequestError as e:
            logger.error("mcp_proxy_error", error=str(e), target=target_url)
            return Response(
                content=json.dumps({"error": "proxy_error", "message": str(e)}),
                status_code=502,
                media_type="application/json",
            )
    
    async def proxy_oauth_metadata(self, request: Request) -> Response:
        """Proxy OAuth authorization server metadata."""
        try:
            response = await self.client.get(
                f"{self.auth_server_url}/.well-known/oauth-authorization-server"
            )
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type="application/json",
            )
        except httpx.RequestError as e:
            logger.error("oauth_metadata_proxy_error", error=str(e))
            return Response(
                content=json.dumps({"error": "proxy_error", "message": str(e)}),
                status_code=502,
                media_type="application/json",
            )
    
    async def proxy_openid_config(self, request: Request) -> Response:
        """Proxy OpenID Connect configuration."""
        try:
            response = await self.client.get(
                f"{self.auth_server_url}/.well-known/openid-configuration"
            )
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type="application/json",
            )
        except httpx.RequestError as e:
            logger.error("openid_config_proxy_error", error=str(e))
            return Response(
                content=json.dumps({"error": "proxy_error", "message": str(e)}),
                status_code=502,
                media_type="application/json",
            )
    
    async def proxy_request(self, request: Request) -> Response:
        """Generic request proxy for non-MCP endpoints."""
        path = request.path_params.get("path", "")
        target_url = f"{self.mcp_server_url}/{path}"
        
        # Get request details
        headers = dict(request.headers)
        headers.pop("host", None)
        
        # Process authentication if present
        if self.auth_interceptor and "authorization" in headers:
            new_headers = await self.auth_interceptor.process_auth_header(headers)
            if new_headers:
                headers = new_headers
        
        try:
            # Get body if present
            body = None
            if request.method in ["POST", "PUT", "PATCH"]:
                body = await request.body()
            
            # Make the proxied request
            response = await self.client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                params=dict(request.query_params),
            )
            
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
            )
            
        except httpx.RequestError as e:
            logger.error("generic_proxy_error", error=str(e), target=target_url)
            return Response(
                content=json.dumps({"error": "proxy_error", "message": str(e)}),
                status_code=502,
                media_type="application/json",
            )
    
    async def health_check(self, request: Request) -> Response:
        """Health check endpoint."""
        health_status = {
            "status": "healthy",
            "gateway": "mcp-auth-gateway",
            "auth_server": self.auth_server_url,
            "mcp_server": self.mcp_server_url,
            "token_exchange": self.token_handler is not None,
        }
        return Response(
            content=json.dumps(health_status),
            status_code=200,
            media_type="application/json",
        )
    
    async def run(self):
        """Run the gateway server."""
        config = uvicorn.Config(
            app=self.app,
            host=self.host,
            port=self.port,
            log_level="debug" if self.debug else "info",
            access_log=self.debug,
        )
        server = uvicorn.Server(config)
        await server.serve()