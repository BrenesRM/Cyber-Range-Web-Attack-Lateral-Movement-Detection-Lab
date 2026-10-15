import http.server
import socketserver
import json

PORT = 5000

class CorporateApiHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/v1/customers':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            data = {
                "status": "RESTRICTED",
                "department": "Internal Core Banking",
                "records": [
                    {"id": 1001, "name": "ACME Corp", "balance": 1500000},
                    {"id": 1002, "name": "Wayne Enterprises", "balance": 9800000}
                ]
            }
            self.wfile.write(json.dumps(data).encode())
        elif self.path == '/api/v1/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"healthy","service":"internal-db"}')
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    print(f"[*] Internal Corporate API listening on port {PORT}...")
    with socketserver.TCPServer(("", PORT), CorporateApiHandler) as httpd:
        httpd.serve_forever()
