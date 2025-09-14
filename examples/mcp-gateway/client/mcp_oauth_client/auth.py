"""
OAuth callback server and authentication utilities.

Handles OAuth authorization code flow with local callback server.
"""

import asyncio
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional, Tuple
from urllib.parse import parse_qs, urlparse

from rich.console import Console

console = Console()


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth callback."""
    
    def __init__(self, request, client_address, server, callback_data):
        """Initialize with callback data storage."""
        self.callback_data = callback_data
        super().__init__(request, client_address, server)
    
    def do_GET(self):
        """Handle GET request from OAuth redirect."""
        parsed = urlparse(self.path)
        query_params = parse_qs(parsed.query)
        
        if "code" in query_params:
            self.callback_data["authorization_code"] = query_params["code"][0]
            self.callback_data["state"] = query_params.get("state", [None])[0]
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write("""
            <html>
            <head>
                <title>Authorization Successful</title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        background-color: #f0f2f5;
                    }
                    .container {
                        text-align: center;
                        padding: 2rem;
                        background: white;
                        border-radius: 8px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    }
                    h1 { color: #10b981; margin-bottom: 0.5rem; }
                    p { color: #6b7280; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>✓ Authorization Successful!</h1>
                    <p>You can close this window and return to the terminal.</p>
                </div>
                <script>setTimeout(() => window.close(), 3000);</script>
            </body>
            </html>
            """.encode())
        elif "error" in query_params:
            self.callback_data["error"] = query_params["error"][0]
            error_description = query_params.get("error_description", ["Unknown error"])[0]
            self.send_response(400)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(f"""
            <html>
            <head>
                <title>Authorization Failed</title>
                <style>
                    body {{
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        background-color: #f0f2f5;
                    }}
                    .container {{
                        text-align: center;
                        padding: 2rem;
                        background: white;
                        border-radius: 8px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    }}
                    h1 {{ color: #ef4444; margin-bottom: 0.5rem; }}
                    p {{ color: #6b7280; }}
                    .error {{ 
                        background: #fef2f2; 
                        padding: 1rem; 
                        border-radius: 4px; 
                        margin-top: 1rem;
                        color: #991b1b;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>✗ Authorization Failed</h1>
                    <p>You can close this window and return to the terminal.</p>
                    <div class="error">
                        <strong>Error:</strong> {query_params["error"][0]}<br>
                        <strong>Description:</strong> {error_description}
                    </div>
                </div>
            </body>
            </html>
            """.encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


class CallbackServer:
    """OAuth callback server that runs in background thread."""
    
    def __init__(self, port: int = 8080):
        """Initialize callback server with specified port."""
        self.port = port
        self.server = None
        self.thread = None
        self.callback_data = {
            "authorization_code": None,
            "state": None,
            "error": None
        }
    
    def _create_handler_with_data(self):
        """Create a handler class with access to callback data."""
        callback_data = self.callback_data
        
        class DataCallbackHandler(CallbackHandler):
            def __init__(self, request, client_address, server):
                super().__init__(request, client_address, server, callback_data)
        
        return DataCallbackHandler
    
    def start(self):
        """Start the callback server in a background thread."""
        handler_class = self._create_handler_with_data()
        self.server = HTTPServer(("localhost", self.port), handler_class)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        console.print(f"[dim]Started OAuth callback server on http://localhost:{self.port}[/dim]")
    
    def stop(self):
        """Stop the callback server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=1)
    
    def wait_for_callback(self, timeout: float = 300) -> str:
        """Wait for OAuth callback with timeout."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.callback_data["authorization_code"]:
                return self.callback_data["authorization_code"]
            elif self.callback_data["error"]:
                raise Exception(f"OAuth error: {self.callback_data['error']}")
            time.sleep(0.1)
        raise Exception("Timeout waiting for OAuth callback")
    
    def get_state(self) -> Optional[str]:
        """Get the received state parameter."""
        return self.callback_data["state"]


async def handle_oauth_callback(port: int = 8080) -> Tuple[str, Optional[str]]:
    """Handle OAuth callback and return authorization code and state."""
    callback_server = CallbackServer(port=port)
    callback_server.start()
    
    try:
        console.print("[yellow]Waiting for authorization callback...[/yellow]")
        auth_code = callback_server.wait_for_callback(timeout=300)
        state = callback_server.get_state()
        return auth_code, state
    finally:
        callback_server.stop()


async def open_browser(url: str) -> None:
    """Open authorization URL in default browser."""
    console.print(f"[green]Opening browser for authorization...[/green]")
    console.print(f"[dim]URL: {url}[/dim]")
    
    # Parse and log the authorization URL parameters
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    # Log the requested scopes if present
    if 'scope' in params:
        scopes = params['scope'][0] if params['scope'] else 'None'
        console.print(f"[cyan]Requested scopes: {scopes}[/cyan]")
    else:
        console.print(f"[yellow]No scopes specified in authorization request[/yellow]")
    
    # Log other important OAuth parameters
    if 'response_type' in params:
        console.print(f"[dim]Response type: {params['response_type'][0]}[/dim]")
    if 'client_id' in params:
        console.print(f"[dim]Client ID: {params['client_id'][0]}[/dim]")
    
    # Run in thread to avoid blocking
    await asyncio.get_event_loop().run_in_executor(
        None, webbrowser.open, url
    )