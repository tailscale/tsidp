"""OAuth 2.0 Dynamic Client Registration (RFC 7591)."""

import secrets
import string
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

import httpx


class ClientRegistrationError(Exception):
    """Error during OAuth client registration process."""
    pass


@dataclass
class RegisteredClient:
    """OAuth client registration information."""
    client_id: str
    client_secret: Optional[str]
    client_name: str
    redirect_uris: List[str]
    grant_types: List[str]
    token_endpoint_auth_method: str
    application_type: str = "web"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "client_name": self.client_name,
            "redirect_uris": self.redirect_uris,
            "grant_types": self.grant_types,
            "token_endpoint_auth_method": self.token_endpoint_auth_method,
            "application_type": self.application_type,
        }


def generate_client_name(base_name: str = "MCP Auth Server") -> str:
    """Generate a unique client name with random suffix.
    
    Args:
        base_name: Base name for the client
        
    Returns:
        Unique client name with random suffix
    """
    # Generate random suffix for uniqueness
    suffix = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
    return f"{base_name}-{suffix}"


async def register_oauth_client(
    registration_endpoint: str,
    client_name: str,
    server_url: str,
    timeout: float = 10.0,
) -> RegisteredClient:
    """Register a new OAuth 2.0 client via dynamic registration.
    
    Implements RFC 7591 - OAuth 2.0 Dynamic Client Registration Protocol
    
    Args:
        registration_endpoint: Dynamic registration endpoint URL
        client_name: Name for the client registration
        server_url: This server's base URL (for redirect URI)
        timeout: HTTP request timeout in seconds
        
    Returns:
        Registered client information
        
    Raises:
        ClientRegistrationError: If registration fails
    """
    # Construct redirect URI for this server
    redirect_uri = f"{server_url.rstrip('/')}/oauth/callback"
    
    # RFC 7591: Client registration request
    registration_request = {
        "client_name": client_name,
        "redirect_uris": [redirect_uri],
        "grant_types": ["client_credentials"],  # For service-to-service auth
        "token_endpoint_auth_method": "client_secret_post",  # Match tsidp behavior
        "application_type": "web",
    }
    
    try:
        async with httpx.AsyncClient(
            verify=True,
            timeout=timeout,
            follow_redirects=False,  # Security: no redirects for registration
        ) as client:
            
            response = await client.post(
                registration_endpoint,
                json=registration_request,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            
            if response.status_code == 400:
                try:
                    error_data = response.json()
                    error_desc = error_data.get("error_description", "Bad request")
                except:
                    error_desc = response.text or "Bad request"
                raise ClientRegistrationError(f"Registration failed: {error_desc}")
            
            if response.status_code == 401:
                raise ClientRegistrationError(
                    "Registration endpoint requires authentication (not supported)"
                )
            
            if response.status_code == 403:
                raise ClientRegistrationError(
                    "Registration forbidden - server may not support dynamic registration"
                )
            
            if response.status_code != 201:
                raise ClientRegistrationError(
                    f"Registration failed with status {response.status_code}: {response.text}"
                )
            
            try:
                registration_response = response.json()
            except Exception as e:
                raise ClientRegistrationError(f"Invalid JSON in registration response: {e}")
            
            # Validate required fields in response
            client_id = registration_response.get("client_id")
            if not client_id:
                raise ClientRegistrationError("Missing client_id in registration response")
            
            client_secret = registration_response.get("client_secret")
            # client_secret may be optional for public clients, but we need it for introspection
            if not client_secret:
                raise ClientRegistrationError(
                    "Missing client_secret in registration response (required for introspection auth)"
                )
            
            return RegisteredClient(
                client_id=client_id,
                client_secret=client_secret,
                client_name=registration_response.get("client_name", client_name),
                redirect_uris=registration_response.get("redirect_uris", [redirect_uri]),
                grant_types=registration_response.get("grant_types", ["client_credentials"]),
                token_endpoint_auth_method=registration_response.get(
                    "token_endpoint_auth_method", "client_secret_post"
                ),
                application_type=registration_response.get("application_type", "web"),
            )
            
    except httpx.RequestError as e:
        raise ClientRegistrationError(f"Network error during registration: {e}")
    except ClientRegistrationError:
        # Re-raise our own exceptions
        raise
    except Exception as e:
        raise ClientRegistrationError(f"Unexpected error during registration: {e}")


async def validate_registration_support(
    registration_endpoint: str,
    timeout: float = 5.0,
) -> bool:
    """Check if the registration endpoint is accessible.
    
    Args:
        registration_endpoint: Registration endpoint URL
        timeout: HTTP request timeout in seconds
        
    Returns:
        True if endpoint appears to be accessible
    """
    try:
        async with httpx.AsyncClient(
            verify=True,
            timeout=timeout,
        ) as client:
            
            # Send OPTIONS request to check if endpoint exists
            response = await client.options(registration_endpoint)
            
            # Accept any response that's not 404
            return response.status_code != 404
            
    except Exception:
        # Any error means we can't validate - assume it works
        return True