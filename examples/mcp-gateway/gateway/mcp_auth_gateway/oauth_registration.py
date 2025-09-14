"""OAuth client registration for the gateway."""

import json
import socket
from typing import Optional
from datetime import datetime

import httpx
import structlog
from pydantic import BaseModel

logger = structlog.get_logger(__name__)


class OAuthServerMetadata(BaseModel):
    """OAuth 2.0 Authorization Server Metadata."""
    
    issuer: str
    token_endpoint: str
    introspection_endpoint: Optional[str] = None
    registration_endpoint: Optional[str] = None
    jwks_uri: Optional[str] = None
    scopes_supported: Optional[list[str]] = None
    response_types_supported: Optional[list[str]] = None
    grant_types_supported: Optional[list[str]] = None
    token_endpoint_auth_methods_supported: Optional[list[str]] = None


class RegisteredClient(BaseModel):
    """Registered OAuth client information."""
    
    client_id: str
    client_secret: Optional[str] = None
    client_name: Optional[str] = None
    redirect_uris: Optional[list[str]] = None
    token_endpoint_auth_method: Optional[str] = None
    grant_types: Optional[list[str]] = None
    response_types: Optional[list[str]] = None
    scope: Optional[str] = None


async def discover_oauth_metadata(auth_server_url: str) -> OAuthServerMetadata:
    """Discover OAuth 2.0 Authorization Server metadata.
    
    Args:
        auth_server_url: Base URL of the authorization server
        
    Returns:
        OAuth server metadata
        
    Raises:
        Exception: If discovery fails
    """
    auth_server_url = auth_server_url.rstrip("/")
    
    # Try different discovery endpoints
    discovery_urls = [
        f"{auth_server_url}/.well-known/oauth-authorization-server",
        f"{auth_server_url}/.well-known/openid-configuration",
    ]
    
    async with httpx.AsyncClient() as client:
        for url in discovery_urls:
            try:
                logger.debug("attempting_oauth_discovery", url=url)
                response = await client.get(url)
                if response.status_code == 200:
                    metadata = response.json()
                    logger.info("oauth_discovery_success", endpoint=url)
                    return OAuthServerMetadata(**metadata)
            except Exception as e:
                logger.debug("oauth_discovery_failed", url=url, error=str(e))
                continue
    
    raise Exception(f"Failed to discover OAuth metadata from {auth_server_url}")


async def register_oauth_client(
    registration_endpoint: str,
    client_name: str,
    gateway_url: str,
) -> RegisteredClient:
    """Register as an OAuth client with the authorization server.
    
    Args:
        registration_endpoint: OAuth dynamic client registration endpoint
        client_name: Name for the client
        gateway_url: The gateway's own URL
        
    Returns:
        Registered client information including client_id and client_secret
        
    Raises:
        Exception: If registration fails
    """
    # Prepare registration request per RFC 7591
    registration_request = {
        "client_name": client_name,
        "grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange"],
        "token_endpoint_auth_method": "client_secret_post",
        # Gateway doesn't need redirect URIs since it only does token exchange
        # But some servers may require it
        "redirect_uris": [f"{gateway_url}/callback"],
        "scope": "openid profile email",  # Request common scopes
    }
    
    logger.debug("registering_oauth_client", endpoint=registration_endpoint, client_name=client_name)
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                registration_endpoint,
                json=registration_request,
                headers={"Content-Type": "application/json"},
            )
            
            if response.status_code not in [200, 201]:
                error_detail = response.text
                try:
                    error_json = response.json()
                    error_detail = error_json.get("error_description", error_detail)
                except:
                    pass
                raise Exception(f"Registration failed (HTTP {response.status_code}): {error_detail}")
            
            client_info = response.json()
            logger.info(
                "oauth_client_registered",
                client_id=client_info.get("client_id"),
                client_name=client_info.get("client_name"),
            )
            
            return RegisteredClient(**client_info)
            
        except httpx.RequestError as e:
            raise Exception(f"Network error during registration: {e}")


def generate_client_name() -> str:
    """Generate a unique client name for the gateway.
    
    Returns:
        A client name like "MCP Gateway (hostname) 2024-01-06T10:30:00"
    """
    hostname = socket.gethostname()
    timestamp = datetime.now().isoformat(timespec='seconds')
    return f"MCP Gateway ({hostname}) {timestamp}"