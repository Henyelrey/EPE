"""Origen de pruebas para la demostración: sirve un archivo cacheable en el puerto 8099.

Escucha en 127.0.0.1, o en la dirección que se pase como argumento (el laboratorio usa 0.0.0.0).
"""
import sys
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


ThreadingHTTPServer((sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1", 8099), Handler).serve_forever()
