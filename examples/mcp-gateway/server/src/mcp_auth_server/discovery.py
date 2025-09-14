"""OAuth 2.0 Authorization Server discovery (RFC 8414)."""

from typing import Optional, Dict, Any
from urllib.parse import urljoin

import httpx


class OAuthDiscoveryError(Exception):
    """Error during OAuth discovery process."""
    pass


class AuthorizationServerMetadata:
    """OAuth 2.0 Authorization Server Metadata."""
    
    def __init__(self, metadata: Dict[str, Any]):
        """Initialize from discovery response."""
        self.raw_metadata = metadata
        self.issuer = metadata.get("issuer")
        self.authorization_endpoint = metadata.get("authorization_endpoint")
        self.token_endpoint = metadata.get("token_endpoint")
        self.introspection_endpoint = metadata.get("introspection_endpoint")
        self.registration_endpoint = metadata.get("registration_endpoint")
        self.jwks_uri = metadata.get("jwks_uri")
        self.scopes_supported = metadata.get("scopes_supported", [])
        self.grant_types_supported = metadata.get("grant_types_supported", [])
        self.token_endpoint_auth_methods_supported = metadata.get(
            "token_endpoint_auth_methods_supported", []
        )
        self.introspection_endpoint_auth_methods_supported = metadata.get(
            "introspection_endpoint_auth_methods_supported", []
        )
    
    def validate(self) -> None:
        """Validate required fields are present."""
        if not self.issuer:
            raise OAuthDiscoveryError("Missing required 'issuer' field")
        
        if not self.introspection_endpoint:
            raise OAuthDiscoveryError("Missing required 'introspection_endpoint' field")
        
        if not self.registration_endpoint:
            raise OAuthDiscoveryError("Missing required 'registration_endpoint' field")


async def discover_authorization_server(
    auth_server_url: str,
    timeout: float = 10.0,
) -> AuthorizationServerMetadata:
    """Discover OAuth 2.0 Authorization Server metadata.
    
    Implements RFC 8414 - OAuth 2.0 Authorization Server Metadata
    
    Args:
        auth_server_url: Base URL of the authorization server
        timeout: HTTP request timeout in seconds
        
    Returns:
        Authorization server metadata
        
    Raises:
        OAuthDiscoveryError: If discovery fails or metadata is invalid
    """
    # RFC 8414: Authorization server metadata endpoint
    discovery_url = urljoin(
        auth_server_url.rstrip("/") + "/",
        ".well-known/oauth-authorization-server"
    )
    
    try:
        async with httpx.AsyncClient(
            verify=True,
            timeout=timeout,
            follow_redirects=True,
        ) as client:
            
            response = await client.get(
                discovery_url,
                headers={"Accept": "application/json"},
            )
            
            if response.status_code == 404:
                raise OAuthDiscoveryError(
                    f"Authorization server does not support discovery (404 at {discovery_url})"
                )
            
            if response.status_code != 200:
                raise OAuthDiscoveryError(
                    f"Discovery failed with status {response.status_code}: {response.text}"
                )
            
            try:
                metadata_dict = response.json()
            except Exception as e:
                raise OAuthDiscoveryError(f"Invalid JSON in discovery response: {e}")
            
            metadata = AuthorizationServerMetadata(metadata_dict)
            metadata.validate()
            
            return metadata
            
    except httpx.RequestError as e:
        raise OAuthDiscoveryError(f"Network error during discovery: {e}")
    except OAuthDiscoveryError:
        # Re-raise our own exceptions
        raise
    except Exception as e:
        raise OAuthDiscoveryError(f"Unexpected error during discovery: {e}")


async def check_server_support(metadata: AuthorizationServerMetadata) -> Dict[str, bool]:
    """Check what features the authorization server supports.
    
    Args:
        metadata: Authorization server metadata
        
    Returns:
        Dictionary of supported features
    """
    return {
        "dynamic_registration": bool(metadata.registration_endpoint),
        "token_introspection": bool(metadata.introspection_endpoint),
        "client_credentials_grant": "client_credentials" in metadata.grant_types_supported,
        "client_secret_post_auth": "client_secret_post" in metadata.token_endpoint_auth_methods_supported,
        "client_secret_basic_auth": "client_secret_basic" in metadata.token_endpoint_auth_methods_supported,
        "introspection_client_auth": bool(metadata.introspection_endpoint_auth_methods_supported),
    }