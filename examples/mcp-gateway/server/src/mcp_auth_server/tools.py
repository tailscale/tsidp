"""Protected tools that require OAuth authentication."""

import logging
from typing import Dict, Any

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.auth.middleware.auth_context import get_access_token, auth_context_var

logger = logging.getLogger(__name__)


def register_tools(app: FastMCP) -> None:
    """Register authenticated tools with the MCP server."""
    
    @app.tool()
    async def debug_auth(ctx: Context) -> Dict[str, Any]:
        """Debug authentication by showing both header and context token info.
        
        This tool helps diagnose authentication issues by displaying
        what token is in the Authorization header vs what's in the context.
        
        Returns:
            Dictionary with detailed auth debugging information
        """
        import time
        from starlette.requests import Request
        
        # Get authentication information from context
        access_token = get_access_token()
        
        # Try to get the request object to check the actual header
        header_token = None
        try:
            # Access the underlying request if available
            if hasattr(ctx, '_request_context') and ctx._request_context:
                scope = ctx._request_context.scope
                headers = dict(scope.get('headers', []))
                auth_header = headers.get(b'authorization', b'').decode('utf-8')
                if auth_header.startswith('Bearer '):
                    header_token = auth_header[7:]
        except Exception as e:
            logger.error(f"Failed to extract header token: {e}")
        
        current_time = int(time.time())
        
        result = {
            "current_time": current_time,
            "request_id": ctx.request_id,
            "context_token": None,
            "header_token": None,
            "tokens_match": False,
        }
        
        if access_token:
            result["context_token"] = {
                "token_preview": f"{access_token.token[:8]}...{access_token.token[-8:]}" if len(access_token.token) > 16 else "[short]",
                "client_id": access_token.client_id,
                "expires_at": access_token.expires_at,
                "is_expired": current_time >= access_token.expires_at if access_token.expires_at else None,
                "time_until_expiry": access_token.expires_at - current_time if access_token.expires_at else None,
            }
        
        if header_token:
            result["header_token"] = {
                "token_preview": f"{header_token[:8]}...{header_token[-8:]}" if len(header_token) > 16 else "[short]",
            }
            
            # Check if tokens match
            if access_token and header_token:
                result["tokens_match"] = access_token.token == header_token
        
        logger.info(f"Debug auth result: {result}")
        
        return result
    
    @app.tool()
    async def multiply(a: float, b: float, ctx: Context) -> Dict[str, Any]:
        """Multiply two numbers.
        
        This tool requires OAuth authentication and returns the product 
        of two input numbers along with authentication context.
        
        Args:
            a: First number to multiply
            b: Second number to multiply
            
        Returns:
            Dictionary with result and authentication info
        """
        # Get authentication information from context
        access_token = get_access_token()
        client_id = access_token.client_id if access_token else "unknown"
        
        result = a * b
        
        return {
            "operation": "multiplication",
            "inputs": {"a": a, "b": b},
            "result": result,
            "authenticated_as": client_id,
            "request_id": ctx.request_id,
        }
    
    @app.tool()
    async def oauth_details(ctx: Context) -> Dict[str, Any]:
        """Get OAuth authentication details for the current client.
        
        Returns all available OAuth token information that the server
        knows about the authenticated client.
        
        Returns:
            Dictionary with OAuth client and token details
        """
        # Get authentication information from context
        access_token = get_access_token()
        
        if not access_token:
            logger.warning("oauth_details called but no access token available")
            return {
                "error": "No client authentication available",
                "authenticated": False,
            }
        
        # Add current time for debugging
        import time
        current_time = int(time.time())
        
        # Log token details
        logger.info(f"oauth_details called for client {access_token.client_id}")
        logger.info(f"Token: {access_token.token[:8]}...{access_token.token[-8:] if len(access_token.token) > 16 else '[short]'}")
        logger.info(f"Token expires_at: {access_token.expires_at}")
        logger.info(f"Current time: {current_time}")
        logger.info(f"Request ID: {ctx.request_id}")
        
        # Calculate time until expiration if expires_at is set
        time_until_expiry = None
        is_expired = False
        if access_token.expires_at:
            time_until_expiry = access_token.expires_at - current_time
            is_expired = current_time >= access_token.expires_at
        
        return {
            "authenticated": True,
            "client_id": access_token.client_id,
            "scopes": access_token.scopes,
            "expires_at": access_token.expires_at,
            "resource": access_token.resource,
            "request_id": ctx.request_id,
            "token_type": "Bearer",
            # Additional debugging information
            "current_time": current_time,
            "time_until_expiry": time_until_expiry,
            "is_expired": is_expired,
            "token_preview": f"{access_token.token[:8]}...{access_token.token[-8:]}" if len(access_token.token) > 16 else "[short token]",
        }