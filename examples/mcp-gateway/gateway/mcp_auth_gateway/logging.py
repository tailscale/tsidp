"""Logging configuration for the MCP Gateway."""

import logging
import sys
from typing import Any, Dict

import structlog
from rich.console import Console
from rich.logging import RichHandler

console = Console()


def setup_logging(debug: bool = False) -> None:
    """Configure structured logging with optional debug mode.
    
    Args:
        debug: Enable detailed debug logging
    """
    # Configure standard logging
    log_level = logging.DEBUG if debug else logging.INFO
    
    # Setup rich handler for better console output
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        handlers=[
            RichHandler(
                console=console,
                show_time=True,
                show_path=debug,
                rich_tracebacks=True,
            )
        ],
    )
    
    # Configure structlog
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]
    
    if debug:
        # Add more detailed processors for debug mode
        processors.append(structlog.processors.CallsiteParameterAdder())
    
    # Add final renderer
    processors.append(structlog.dev.ConsoleRenderer())
    
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Set log levels for specific modules
    if debug:
        logging.getLogger("httpx").setLevel(logging.DEBUG)
        logging.getLogger("mcp").setLevel(logging.DEBUG)
        logging.getLogger("mcp_auth_gateway").setLevel(logging.DEBUG)
    else:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("mcp").setLevel(logging.INFO)
        logging.getLogger("mcp_auth_gateway").setLevel(logging.INFO)


class RequestLogger:
    """Logger for HTTP requests and responses in debug mode."""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.logger = structlog.get_logger(__name__)
        self.request_counter = 0
    
    def log_request(self, method: str, url: str, headers: Dict[str, Any], body: Any = None) -> int:
        """Log an outgoing HTTP request.
        
        Returns:
            Request ID for correlation
        """
        if not self.debug:
            return 0
        
        self.request_counter += 1
        request_id = self.request_counter
        
        self.logger.debug(
            "outgoing_request",
            request_id=request_id,
            method=method,
            url=url,
            headers=dict(headers) if headers else {},
            body_preview=str(body)[:500] if body else None,
        )
        
        return request_id
    
    def log_response(self, request_id: int, status: int, headers: Dict[str, Any], body: Any = None) -> None:
        """Log an incoming HTTP response."""
        if not self.debug:
            return
        
        self.logger.debug(
            "incoming_response",
            request_id=request_id,
            status=status,
            headers=dict(headers) if headers else {},
            body_preview=str(body)[:500] if body else None,
        )
    
    def log_token_exchange(self, subject_token: str, audience: str, resource: str = None) -> None:
        """Log a token exchange request."""
        if not self.debug:
            return
        
        # Safely truncate tokens for logging
        token_preview = f"{subject_token[:8]}...{subject_token[-8:]}" if len(subject_token) > 16 else "[short]"
        
        self.logger.info(
            "token_exchange",
            subject_token_preview=token_preview,
            audience=audience,
            resource=resource,
        )
    
    def log_auth_header(self, header_value: str, action: str = "forwarding") -> None:
        """Log authorization header handling."""
        if not self.debug:
            return
        
        # Safely log bearer tokens
        if header_value.startswith("Bearer "):
            token = header_value[7:]
            token_preview = f"Bearer {token[:8]}...{token[-8:]}" if len(token) > 16 else "Bearer [short]"
        else:
            token_preview = "[non-bearer auth]"
        
        self.logger.debug(
            "auth_header",
            action=action,
            auth_preview=token_preview,
        )