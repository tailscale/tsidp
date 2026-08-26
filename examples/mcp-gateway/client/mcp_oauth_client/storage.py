"""
Token storage implementation for MCP OAuth client.

Provides persistent storage for OAuth tokens and client information.
Storage is keyed by server URL to support multiple servers.
"""

import json
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from mcp.client.auth import TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken


class FileTokenStorage(TokenStorage):
    """File-based token storage implementation.

    Storage files are keyed by server URL to prevent credential conflicts
    when connecting to multiple servers.
    """

    def __init__(self, server_url: str, storage_dir: Optional[Path] = None):
        """Initialize file storage with server URL for cache key generation.

        Args:
            server_url: The MCP server URL (used to generate unique cache keys)
            storage_dir: Optional custom storage directory. Defaults to
                        .oauth-cache in the client package directory.
        """
        self.server_url = server_url

        if storage_dir is None:
            # Store in .oauth-cache directory next to this module
            storage_dir = Path(__file__).parent.parent / '.oauth-cache'

        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_key(self) -> str:
        """Generate a safe filesystem key from the server URL."""
        parsed = urlparse(self.server_url)
        # Use scheme, host, and port to create unique key
        base_url = f"{parsed.scheme}_{parsed.netloc}"
        # Replace characters that are problematic in filenames
        return base_url.replace(":", "_").replace("/", "_").replace(".", "_")

    def _get_file_path(self, file_type: str) -> Path:
        """Get the file path for a specific storage type."""
        key = self._get_cache_key()
        return self.storage_dir / f"{key}_{file_type}.json"
    
    async def get_tokens(self) -> Optional[OAuthToken]:
        """Get stored tokens from file."""
        tokens_file = self._get_file_path("tokens")
        if tokens_file.exists():
            try:
                with open(tokens_file, 'r') as f:
                    data = json.load(f)
                return OAuthToken.model_validate(data)
            except Exception:
                # If file is corrupted or invalid, return None
                return None
        return None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        """Store tokens to file."""
        tokens_file = self._get_file_path("tokens")
        with open(tokens_file, 'w') as f:
            json.dump(tokens.model_dump(mode='json', exclude_none=True), f, indent=2)
        # Set restrictive permissions on tokens file
        tokens_file.chmod(0o600)

    async def get_client_info(self) -> Optional[OAuthClientInformationFull]:
        """Get stored client information from file."""
        client_info_file = self._get_file_path("client_info")
        if client_info_file.exists():
            try:
                with open(client_info_file, 'r') as f:
                    data = json.load(f)
                return OAuthClientInformationFull.model_validate(data)
            except Exception:
                # If file is corrupted or invalid, return None
                return None
        return None

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        """Store client information to file."""
        client_info_file = self._get_file_path("client_info")
        with open(client_info_file, 'w') as f:
            json.dump(client_info.model_dump(mode='json', exclude_none=True), f, indent=2)
        # Set restrictive permissions on client info file
        client_info_file.chmod(0o600)

    def clear_all(self) -> None:
        """Clear all stored data for the current server."""
        tokens_file = self._get_file_path("tokens")
        client_info_file = self._get_file_path("client_info")
        if tokens_file.exists():
            tokens_file.unlink()
        if client_info_file.exists():
            client_info_file.unlink()