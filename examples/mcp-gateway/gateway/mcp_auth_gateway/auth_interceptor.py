"""Authentication interceptor for processing and exchanging tokens."""

import re
from typing import Dict, Optional, Any

import structlog

from .token_exchange import TokenExchangeHandler, TokenExchangeError

logger = structlog.get_logger(__name__)


class AuthInterceptor:
    """Intercepts and processes authentication headers for token exchange."""
    
    def __init__(
        self,
        token_handler: Optional[TokenExchangeHandler],
        mcp_server_url: str,
        debug: bool = False,
        gateway_server=None,
        default_scopes: Optional[str] = None,
    ):
        """Initialize the auth interceptor.
        
        Args:
            token_handler: Token exchange handler (may be None if not configured)
            mcp_server_url: Target MCP server URL (used as resource in token exchange)
            debug: Enable debug logging
            gateway_server: Reference to gateway server for statistics
            default_scopes: Default scopes to request if none found in original token
        """
        self.token_handler = token_handler
        self.mcp_server_url = mcp_server_url
        self.debug = debug
        self.gateway_server = gateway_server
        self.default_scopes = default_scopes or "openid profile email"
    
    async def process_auth_header(self, headers: Dict[str, str]) -> Optional[Dict[str, str]]:
        """Process authorization header, always exchanging the token.
        
        Args:
            headers: Request headers dictionary
            
        Returns:
            Modified headers with exchanged token, or None if no changes needed
        """
        auth_header = headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            # Not a bearer token, pass through unchanged
            if self.debug:
                logger.debug("auth_interceptor_passthrough", reason="not_bearer_token")
            return None
        
        # Extract the bearer token
        original_token = auth_header[7:]  # Remove "Bearer " prefix
        
        if self.debug:
            token_preview = f"{original_token[:8]}...{original_token[-8:]}" if len(original_token) > 16 else "[short]"
            logger.debug("auth_interceptor_processing", token_preview=token_preview)
        
        # Skip exchange if token handler not available
        if not self.token_handler:
            if self.debug:
                logger.debug("auth_interceptor_passthrough", reason="no_token_handler")
            return None
        
        # Extract scope from original token if possible
        requested_scopes = self._determine_requested_scopes(original_token, headers)
        
        # Perform token exchange
        try:
            if self.debug:
                logger.debug(
                    "auth_interceptor_exchanging",
                    resource=self.mcp_server_url,
                    audience=self.mcp_server_url,
                    requested_scopes=requested_scopes,
                )
            
            # Exchange the token for one valid at the MCP server
            # The client's token has the gateway as audience, we need to exchange it
            # for a token with the MCP server as the audience
            exchange_response = await self.token_handler.exchange_token(
                subject_token=original_token,
                subject_token_type=TokenExchangeHandler.TOKEN_TYPE_ACCESS_TOKEN,
                resource=self.mcp_server_url,  # RFC 8707 resource indicators
                audience=self.mcp_server_url,  # RFC 8693 audience - the MCP server
                scope=requested_scopes,
                requested_token_type=TokenExchangeHandler.TOKEN_TYPE_ACCESS_TOKEN,
            )
            
            if self.debug:
                new_token_preview = (
                    f"{exchange_response.access_token[:8]}...{exchange_response.access_token[-8:]}"
                    if len(exchange_response.access_token) > 16
                    else "[short]"
                )
                logger.debug(
                    "auth_interceptor_exchange_success",
                    new_token_preview=new_token_preview,
                    token_type=exchange_response.token_type,
                    expires_in=exchange_response.expires_in,
                )
            
            # Log successful exchange
            logger.info(
                "token_exchange_successful",
                token_type=exchange_response.token_type,
                expires_in=exchange_response.expires_in,
                scope=exchange_response.scope,
                issued_token_type=exchange_response.issued_token_type,
            )
            
            # Update statistics
            if self.gateway_server:
                self.gateway_server.token_exchanges += 1
            
            # Update headers with new token
            new_headers = headers.copy()
            new_headers["authorization"] = f"Bearer {exchange_response.access_token}"
            return new_headers
            
        except TokenExchangeError as e:
            logger.warning(
                "auth_interceptor_exchange_failed",
                error=e.error,
                error_description=e.error_description,
            )
            # Update statistics
            if self.gateway_server:
                self.gateway_server.exchange_failures += 1
            # Pass through original token on exchange failure
            return None
        except Exception as e:
            logger.error("auth_interceptor_error", error=str(e))
            # Pass through original token on unexpected errors
            return None
    
    def extract_token_claims(self, token: str) -> Optional[Dict[str, Any]]:
        """Extract claims from a JWT token without validation.
        
        This is for debugging purposes only and should not be used for security decisions.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded claims or None if not a valid JWT
        """
        try:
            # JWT has three parts separated by dots
            parts = token.split(".")
            if len(parts) != 3:
                return None
            
            # Decode the payload (second part)
            import base64
            import json
            
            # Add padding if needed
            payload = parts[1]
            padding = 4 - (len(payload) % 4)
            if padding != 4:
                payload += "=" * padding
            
            # Decode from base64
            decoded = base64.urlsafe_b64decode(payload)
            claims = json.loads(decoded)
            
            if self.debug:
                # Log non-sensitive claims
                safe_claims = {
                    k: v for k, v in claims.items()
                    if k not in ["sub", "email", "name", "preferred_username"]
                }
                logger.debug("token_claims_extracted", claims=safe_claims)
            
            return claims
            
        except Exception as e:
            if self.debug:
                logger.debug("token_claims_extraction_failed", error=str(e))
            return None
    
    def should_exchange_token(self, token: str) -> bool:
        """Determine if a token should be exchanged.
        
        This method can be extended to implement more sophisticated logic,
        such as checking token audience, issuer, or expiration.
        
        Args:
            token: Bearer token to evaluate
            
        Returns:
            True if token should be exchanged, False otherwise
        """
        # For now, always attempt exchange if handler is available
        # This could be enhanced to check token claims, audience, etc.
        if not self.token_handler:
            return False
        
        # Could check token claims here
        claims = self.extract_token_claims(token)
        if claims:
            # Check if token is for a different audience/resource
            aud = claims.get("aud")
            if isinstance(aud, str):
                aud = [aud]
            if aud and self.mcp_server_url not in aud:
                # Token is for different audience, should exchange
                if self.debug:
                    logger.debug(
                        "token_audience_mismatch",
                        token_aud=aud,
                        expected=self.mcp_server_url,
                    )
                return True
        
        # Default to attempting exchange
        return True
    
    def _determine_requested_scopes(self, token: str, headers: Dict[str, str]) -> str:
        """Determine what scopes to request in the token exchange.
        
        Args:
            token: Original bearer token
            headers: Request headers (may contain scope information)
            
        Returns:
            Space-separated scope string to request
        """
        # Extract scopes from the original token
        claims = self.extract_token_claims(token)
        if claims and "scope" in claims:
            original_scopes = claims["scope"]
            if isinstance(original_scopes, str):
                token_scopes = original_scopes
            elif isinstance(original_scopes, list):
                token_scopes = " ".join(original_scopes)
            else:
                token_scopes = self.default_scopes
            
            if self.debug:
                logger.debug("using_original_token_scopes", scopes=token_scopes)
            return token_scopes
        
        # Fall back to default scopes if no scope in original token
        if self.debug:
            logger.debug("using_default_scopes", scopes=self.default_scopes)
        return self.default_scopes