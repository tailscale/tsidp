"""OAuth 2.1 token verification for MCP server."""

import logging
import time
from typing import Optional
from urllib.parse import urlparse

import httpx
from mcp.server.auth.provider import AccessToken, TokenVerifier

# Set up logging
logger = logging.getLogger(__name__)


class IntrospectionTokenVerifier(TokenVerifier):
    """Token verifier using OAuth 2.0 Token Introspection (RFC 7662)."""
    
    def __init__(
        self,
        introspection_endpoint: str,
        server_url: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        validate_resource: bool = True,
        timeout: float = 10.0,
    ):
        """Initialize the token verifier.
        
        Args:
            introspection_endpoint: OAuth 2.0 token introspection endpoint URL
            server_url: This resource server's URL (for reference)
            client_id: OAuth client ID for introspection authentication
            client_secret: OAuth client secret for introspection authentication
            validate_resource: Whether to validate token audience (RFC 8707)
            timeout: HTTP request timeout in seconds
        """
        self.introspection_endpoint = introspection_endpoint
        self.server_url = server_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.validate_resource = validate_resource
        self.timeout = timeout
        
        # Security: Validate introspection endpoint to prevent SSRF
        self._validate_introspection_url()
    
    def _validate_introspection_url(self) -> None:
        """Validate introspection endpoint URL to prevent SSRF attacks."""
        try:
            parsed = urlparse(self.introspection_endpoint)
            
            # Only allow HTTPS in production or localhost for development
            if not (
                parsed.scheme == "https" or
                (parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1"))
            ):
                raise ValueError(
                    "Introspection endpoint must use HTTPS or be localhost"
                )
                
            if not parsed.hostname:
                raise ValueError("Invalid introspection endpoint URL")
                
        except Exception as e:
            raise ValueError(f"Invalid introspection endpoint: {e}")
    
    def _validate_resource_claim(self, token_data: dict) -> bool:
        """Validate resource audience claim per RFC 8707.
        
        RFC 8707 specifies that the audience should contain the resource URI
        that was used in the original authorization request. This is typically
        the server URL, but could also be mapped to other identifiers.
        
        For MCP servers, we accept the server URL as specified in RFC 8707.
        """
        if not self.validate_resource:
            return True
            
        # Get audience claim from token data
        audience = token_data.get("aud")
        if not audience:
            logger.debug("No audience claim found in token")
            return False
            
        # RFC 8707: Primary expectation is the resource server URL
        # This should match the 'resource' parameter sent in auth requests
        # For MCP servers, we accept the base server URL as the audience
        acceptable_audiences = [self.server_url]
        
        # Also accept the base URL without path (in case server_url has a path)
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(self.server_url)
        base_url = urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))
        if base_url != self.server_url:
            acceptable_audiences.append(base_url)
        
            
        logger.debug(f"Acceptable audiences: {acceptable_audiences}")
        
        # Handle both string and array audience claims (RFC 7519)
        if isinstance(audience, str):
            is_valid = audience in acceptable_audiences
            logger.debug(f"String audience '{audience}' valid: {is_valid}")
            return is_valid
        elif isinstance(audience, list):
            # RFC 8707: Token valid if any acceptable audience is present
            # But warns this creates "high degree of trust" requirement
            for acceptable_aud in acceptable_audiences:
                if acceptable_aud in audience:
                    logger.debug(f"Found acceptable audience '{acceptable_aud}' in list {audience}")
                    return True
            logger.debug(f"No acceptable audience found in list {audience}")
            return False
            
        logger.debug(f"Invalid audience type: {type(audience)}")
        return False
    
    async def verify_token(self, token: str) -> Optional[AccessToken]:
        """Verify token via OAuth 2.0 token introspection.
        
        Args:
            token: Bearer token to verify
            
        Returns:
            AccessToken if valid, None if invalid or expired
        """
        if not token or not token.strip():
            logger.debug("Token verification failed: empty or missing token")
            return None
        
        # Log token details (truncated for security)
        token_preview = f"{token[:8]}...{token[-8:]}" if len(token) > 16 else "[short token]"
        logger.info(f"Starting token introspection for token: {token_preview}")
        logger.info(f"Introspection endpoint: {self.introspection_endpoint}")
        logger.info(f"Client ID: {self.client_id or 'None'}")
        logger.info(f"Server URL: {self.server_url}")
            
        try:
            async with httpx.AsyncClient(
                verify=True,
                timeout=self.timeout,
                follow_redirects=False,  # Security: prevent redirect attacks
            ) as client:
                
                # RFC 7662: Token introspection request with client authentication
                data = {"token": token}
                
                # Add client authentication if available (matches tsidp pattern)
                if self.client_id and self.client_secret:
                    data.update({
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                    })
                    logger.info(f"Using client credentials authentication: {self.client_id}")
                else:
                    logger.warning("No client credentials available for introspection authentication")
                
                logger.debug(f"Sending introspection request with data keys: {list(data.keys())}")
                
                response = await client.post(
                    self.introspection_endpoint,
                    data=data,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "application/json",
                    },
                )
                
                logger.info(f"Introspection response status: {response.status_code}")
                
                if response.status_code != 200:
                    logger.error(f"Introspection failed with status {response.status_code}: {response.text}")
                    return None
                
                try:
                    token_data = response.json()
                    logger.info(f"Introspection response: {token_data}")
                except Exception as e:
                    logger.error(f"Failed to parse introspection response JSON: {e}")
                    logger.error(f"Response text: {response.text}")
                    return None
                
                # Check if token is active
                is_active = token_data.get("active", False)
                logger.info(f"Token active status: {is_active}")
                if not is_active:
                    logger.warning("Token introspection returned active=false")
                    return None
                
                # Validate token expiry
                exp = token_data.get("exp")
                current_time = int(time.time())
                logger.info(f"Token expiry: {exp}, current time: {current_time}")
                if exp and exp < current_time:
                    logger.warning(f"Token has expired: exp={exp}, now={current_time}")
                    return None
                
                # Validate resource audience per RFC 8707
                audience = token_data.get("aud")
                logger.info(f"Token audience: {audience}")
                logger.info(f"Acceptable audiences: server_url={self.server_url}")
                if not self._validate_resource_claim(token_data):
                    logger.warning(f"RFC 8707 audience validation failed: token aud={audience}, acceptable={self.server_url}")
                    return None
                
                # Extract scopes
                scope_str = token_data.get("scope", "")
                scopes = scope_str.split() if scope_str else []
                logger.info(f"Token scopes: {scopes}")
                
                access_token = AccessToken(
                    token=token,
                    client_id=token_data.get("client_id", "unknown"),
                    scopes=scopes,
                    expires_at=exp,
                    resource=self.server_url,  # RFC 8707: Use resource server URL as primary identifier
                    subject=token_data.get("sub"),
                    issuer=token_data.get("iss"),
                )
                
                logger.info(f"Token validation successful for client: {access_token.client_id}")
                return access_token
                
        except httpx.RequestError as e:
            # Network errors, timeouts, etc.
            logger.error(f"Network error during token introspection: {e}")
            return None
        except Exception as e:
            # Any other unexpected errors
            logger.error(f"Unexpected error during token introspection: {e}")
            return None


def create_token_verifier(
    introspection_endpoint: str,
    server_url: str,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    validate_resource: bool = True,
) -> IntrospectionTokenVerifier:
    """Create a token verifier with OAuth client authentication.
    
    Args:
        introspection_endpoint: OAuth 2.0 token introspection endpoint URL
        server_url: This resource server's URL
        client_id: OAuth client ID for authentication
        client_secret: OAuth client secret for authentication
        validate_resource: Whether to validate token audience
        
    Returns:
        Configured token verifier
    """
    return IntrospectionTokenVerifier(
        introspection_endpoint=introspection_endpoint,
        server_url=server_url,
        client_id=client_id,
        client_secret=client_secret,
        validate_resource=validate_resource,
    )