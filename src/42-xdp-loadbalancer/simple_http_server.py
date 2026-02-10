#!/usr/bin/env python3
"""
Simple HTTP server that doesn't validate the Host header.
This server is designed to work with load balancers that forward requests
with mismatched Host headers.
"""

import sys
import http.server
import socketserver

class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    HTTP request handler that doesn't validate the Host header.
    This allows the server to work behind a load balancer.
    """
    
    def version_string(self):
        """Return the server software version string."""
        return f'SimpleHTTP/{sys.version.split()[0]}'
    
    def log_message(self, format, *args):
        """Log an arbitrary message."""
        # Include the Host header in the log for debugging
        host_header = self.headers.get('Host', 'unknown')
        sys.stderr.write(f"[{self.log_date_time_string()}] Host: {host_header} - {format % args}\n")


def main():
    PORT = 8000
    
    # Allow reuse of address to avoid "Address already in use" errors
    socketserver.TCPServer.allow_reuse_address = True
    
    # Bind to 0.0.0.0 to accept connections from any interface
    with socketserver.TCPServer(("0.0.0.0", PORT), SimpleHTTPRequestHandler) as httpd:
        print(f"Server listening on 0.0.0.0:{PORT}")
        print("This server accepts requests with any Host header.")
        print("Press Ctrl+C to stop the server.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")
            httpd.shutdown()


if __name__ == "__main__":
    main()
