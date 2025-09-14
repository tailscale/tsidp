"""
Token storage implementation for MCP OAuth client.

Provides persistent storage for OAuth tokens and client information.
"""

import json
import os
from pathlib import Path
from typing import Optional

from mcp.client.auth import TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken


class FileTokenStorage(TokenStorage):
    """File-based token storage implementation."""
    
    def __init__(self, storage_dir: Optional[Path] = None):
        """Initialize file storage with optional custom directory."""
        if storage_dir is None:
            # Use XDG_CONFIG_HOME or fallback to ~/.config
            config_home = os.environ.get('XDG_CONFIG_HOME', os.path.expanduser('~/.config'))
            storage_dir = Path(config_home) / 'mcp-oauth-client'
        
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.tokens_file = self.storage_dir / 'tokens.json'
        self.client_info_file = self.storage_dir / 'client_info.json'
    
    async def get_tokens(self) -> Optional[OAuthToken]:
        """Get stored tokens from file."""
        if self.tokens_file.exists():
            try:
                with open(self.tokens_file, 'r') as f:
                    data = json.load(f)
                return OAuthToken.model_validate(data)
            except Exception:
                # If file is corrupted or invalid, return None
                return None
        return None
    
    async def set_tokens(self, tokens: OAuthToken) -> None:
        """Store tokens to file."""
        with open(self.tokens_file, 'w') as f:
            json.dump(tokens.model_dump(mode='json', exclude_none=True), f, indent=2)
        # Set restrictive permissions on tokens file
        self.tokens_file.chmod(0o600)
    
    async def get_client_info(self) -> Optional[OAuthClientInformationFull]:
        """Get stored client information from file."""
        if self.client_info_file.exists():
            try:
                with open(self.client_info_file, 'r') as f:
                    data = json.load(f)
                return OAuthClientInformationFull.model_validate(data)
            except Exception:
                # If file is corrupted or invalid, return None
                return None
        return None
    
    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        """Store client information to file."""
        with open(self.client_info_file, 'w') as f:
            json.dump(client_info.model_dump(mode='json', exclude_none=True), f, indent=2)
        # Set restrictive permissions on client info file
        self.client_info_file.chmod(0o600)
    
    def clear_all(self) -> None:
        """Clear all stored data."""
        if self.tokens_file.exists():
            self.tokens_file.unlink()
        if self.client_info_file.exists():
            self.client_info_file.unlink()