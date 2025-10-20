#!/usr/bin/env python3

import http.server
import socketserver
import os
import threading
import time

class LiffyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/tmp", **kwargs)
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass

def start_server():
    """Start the HTTP server for payload delivery"""
    handler = LiffyHTTPRequestHandler
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("0.0.0.0", 8000), handler) as httpd:
        print(f"HTTP server started on port 8000")
        httpd.serve_forever()

if __name__ == "__main__":
    start_server()

