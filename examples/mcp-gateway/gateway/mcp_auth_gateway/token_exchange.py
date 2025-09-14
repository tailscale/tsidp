"""RFC 8693 OAuth 2.0 Token Exchange implementation."""

import asyncio
from typing import Dict, Optional, Any
from urllib.parse import urlencode

import httpx
import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)


class TokenExchangeRequest(BaseModel):
    """RFC 8693 Token Exchange Request parameters."""
    
    grant_type: str = Field(default="urn:ietf:params:oauth:grant-type:token-exchange")
    subject_token: str = Field(..., description="The token being exchanged")
    subject_token_type: str = Field(
        default="urn:ietf:params:oauth:token-type:access_token",
        description="Type of the subject token"
    )
    resource: Optional[str] = Field(None, description="Target resource server")
    audience: Optional[str] = Field(None, description="Target audience for the token")
    scope: Optional[str] = Field(None, description="Requested scopes")
    requested_token_type: str = Field(
        default="urn:ietf:params:oauth:token-type:access_token",
        description="Type of token being requested"
    )
    actor_token: Optional[str] = Field(None, description="Token representing the acting party")
    actor_token_type: Optional[str] = Field(None, description="Type of the actor token")


class TokenExchangeResponse(BaseModel):
    """RFC 8693 Token Exchange Response."""
    
    access_token: str
    issued_token_type: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    scope: Optional[str] = None
    refresh_token: Optional[str] = None


class TokenExchangeError(Exception):
    """Token exchange error."""
    
    def __init__(self, error: str, error_description: Optional[str] = None):
        self.error = error
        self.error_description = error_description
        super().__init__(f"{error}: {error_description}" if error_description else error)


class TokenExchangeHandler:
    """Handles RFC 8693 OAuth 2.0 Token Exchange operations."""
    
    # Token type URIs from RFC 8693
    TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
    TOKEN_TYPE_REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token"
    TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
    TOKEN_TYPE_SAML1 = "urn:ietf:params:oauth:token-type:saml1"
    TOKEN_TYPE_SAML2 = "urn:ietf:params:oauth:token-type:saml2"
    TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"
    
    def __init__(
        self,
        token_endpoint: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        debug: bool = False,
    ):
        """Initialize token exchange handler.
        
        Args:
            token_endpoint: OAuth 2.0 token endpoint URL
            client_id: Client ID for authentication
            client_secret: Client secret for authentication
            debug: Enable debug logging
        """
        self.token_endpoint = token_endpoint
        self.client_id = client_id
        self.client_secret = client_secret
        self.debug = debug
        self.client = httpx.AsyncClient()
    
    async def close(self) -> None:
        """Close the HTTP client."""
        await self.client.aclose()
    
    async def exchange_token(
        self,
        subject_token: str,
        subject_token_type: str = TOKEN_TYPE_ACCESS_TOKEN,
        resource: Optional[str] = None,
        audience: Optional[str] = None,
        scope: Optional[str] = None,
        requested_token_type: str = TOKEN_TYPE_ACCESS_TOKEN,
        actor_token: Optional[str] = None,
        actor_token_type: Optional[str] = None,
    ) -> TokenExchangeResponse:
        """Exchange a token according to RFC 8693.
        
        Args:
            subject_token: The token to be exchanged
            subject_token_type: Type of the subject token
            resource: Target resource server (RFC 8707)
            audience: Target audience for the new token
            scope: Requested scopes for the new token
            requested_token_type: Type of token being requested
            actor_token: Token representing the acting party
            actor_token_type: Type of the actor token
            
        Returns:
            Token exchange response with the new token
            
        Raises:
            TokenExchangeError: If the exchange fails
        """
        # Build the token exchange request
        request_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": subject_token_type,
            "requested_token_type": requested_token_type,
        }
        
        # Add optional parameters
        if resource:
            request_data["resource"] = resource
        if audience:
            request_data["audience"] = audience
        if scope:
            request_data["scope"] = scope
        if actor_token:
            request_data["actor_token"] = actor_token
            request_data["actor_token_type"] = actor_token_type or self.TOKEN_TYPE_ACCESS_TOKEN
        
        # Add client authentication if available
        if self.client_id and self.client_secret:
            request_data["client_id"] = self.client_id
            request_data["client_secret"] = self.client_secret
        
        if self.debug:
            # Log the exchange request (safely)
            safe_request = request_data.copy()
            if "subject_token" in safe_request:
                token = safe_request["subject_token"]
                safe_request["subject_token"] = f"{token[:8]}...{token[-8:]}" if len(token) > 16 else "[short]"
            if "actor_token" in safe_request:
                token = safe_request["actor_token"]
                safe_request["actor_token"] = f"{token[:8]}...{token[-8:]}" if len(token) > 16 else "[short]"
            if "client_secret" in safe_request:
                safe_request["client_secret"] = "[redacted]"
            
            logger.debug(
                "token_exchange_request",
                endpoint=self.token_endpoint,
                params=safe_request,
            )
        
        try:
            # Make the token exchange request
            response = await self.client.post(
                self.token_endpoint,
                data=request_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            
            if self.debug:
                logger.debug(
                    "token_exchange_response",
                    status=response.status_code,
                    headers=dict(response.headers),
                )
            
            # Check for errors
            if response.status_code != 200:
                error_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                raise TokenExchangeError(
                    error=error_data.get("error", "token_exchange_failed"),
                    error_description=error_data.get("error_description", f"HTTP {response.status_code}"),
                )
            
            # Parse the response
            response_data = response.json()
            
            if self.debug:
                # Log successful exchange (safely)
                safe_response = response_data.copy()
                if "access_token" in safe_response:
                    token = safe_response["access_token"]
                    safe_response["access_token"] = f"{token[:8]}...{token[-8:]}" if len(token) > 16 else "[short]"
                if "refresh_token" in safe_response:
                    token = safe_response["refresh_token"]
                    safe_response["refresh_token"] = f"{token[:8]}...{token[-8:]}" if len(token) > 16 else "[short]"
                
                logger.debug("token_exchange_success", response=safe_response)
            
            return TokenExchangeResponse(**response_data)
            
        except httpx.RequestError as e:
            logger.error("token_exchange_network_error", error=str(e))
            raise TokenExchangeError(
                error="network_error",
                error_description=f"Failed to connect to token endpoint: {e}",
            )
        except Exception as e:
            logger.error("token_exchange_error", error=str(e))
            raise TokenExchangeError(
                error="exchange_failed",
                error_description=str(e),
            )
    
    async def discover_token_endpoint(self, issuer_url: str) -> str:
        """Discover the token endpoint from OAuth metadata.
        
        Args:
            issuer_url: The OAuth issuer URL
            
        Returns:
            The token endpoint URL
            
        Raises:
            TokenExchangeError: If discovery fails
        """
        # Try OAuth 2.0 Authorization Server metadata first
        metadata_urls = [
            f"{issuer_url.rstrip('/')}/.well-known/oauth-authorization-server",
            f"{issuer_url.rstrip('/')}/.well-known/openid-configuration",
        ]
        
        for metadata_url in metadata_urls:
            try:
                response = await self.client.get(metadata_url)
                if response.status_code == 200:
                    metadata = response.json()
                    if "token_endpoint" in metadata:
                        token_endpoint = metadata["token_endpoint"]
                        if self.debug:
                            logger.debug(
                                "discovered_token_endpoint",
                                metadata_url=metadata_url,
                                token_endpoint=token_endpoint,
                            )
                        return token_endpoint
            except httpx.RequestError:
                continue
        
        raise TokenExchangeError(
            error="discovery_failed",
            error_description=f"Could not discover token endpoint from {issuer_url}",
        )
