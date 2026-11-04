"""Origen de pruebas para la demostración: sirve un archivo cacheable en 127.0.0.1:8099."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b"console.log('archivo original de la demo');\n" * 50


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript")
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", 8099), Handler).serve_forever()
