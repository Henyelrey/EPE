"""Origen de prueba: HTTP en :8080 y HTTPS en :8443. Cuenta cuántas veces se le pide cada ruta."""
import http.server, ssl, threading, json, sys, os

HITS = {}
LIB = b"/* libreria */ " + b"x" * 50_000
DYN = {"etag": '"v1"', "body": b'{"precio": 42, "version": 1}'}


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, code, body=b"", headers=None, chunked=False):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(0, len(body), 65536):
                part = body[i:i + 65536]
                self.wfile.write(b"%x\r\n" % len(part) + part + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            return
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        HITS[path] = HITS.get(path, 0) + 1
        if path in ("/static.js", "/copia.js"):
            # Mismo contenido bajo dos URLs → debe deduplicarse en disco.
            return self.send(200, LIB, {"Content-Type": "application/javascript", "Cache-Control": "max-age=60", "ETag": '"lib1"'})
        if path == "/dyn":
            # Contenido dinámico: se guarda pero se revalida siempre (no-cache + ETag).
            if self.headers.get("If-None-Match") == DYN["etag"]:
                return self.send(304, b"", {"ETag": DYN["etag"], "Cache-Control": "no-cache"})
            return self.send(200, DYN["body"], {"Content-Type": "application/json", "Cache-Control": "no-cache", "ETag": DYN["etag"]})
        if path == "/dyn-change":
            DYN["etag"], DYN["body"] = '"v2"', b'{"precio": 45, "version": 2}'
            return self.send(200, b"ok")
        if path == "/private":
            return self.send(200, b"datos de sesion", {"Set-Cookie": "sid=abc", "Cache-Control": "max-age=60"})
        if path == "/perfil":
            # Página personal sin Cache-Control ni Set-Cookie: la cookie de la petición es la única pista.
            who = self.headers.get("Cookie", "anonimo")
            return self.send(200, f"perfil de {who}".encode(), {"Content-Type": "text/html"})
        if path == "/reflect":
            # Origen que arma la respuesta con una cabecera que no forma parte de la clave de caché.
            host = self.headers.get("X-Forwarded-Host", "cdn.legit")
            return self.send(200, f'<script src="//{host}/app.js"></script>'.encode(), {"Cache-Control": "max-age=60"})
        if path == "/big":
            return self.send(200, b"B" * 2_500_000, {"Cache-Control": "max-age=60"}, chunked=True)
        if path == "/__hits":
            return self.send(200, json.dumps(HITS).encode(), {"Content-Type": "application/json", "Cache-Control": "no-store"})
        self.send(404, b"no")


def serve(port, tls):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        d = os.path.dirname(os.path.abspath(__file__))
        ctx.load_cert_chain(os.path.join(d, "origin.pem"), os.path.join(d, "origin.key"))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


threading.Thread(target=serve, args=(8080, False), daemon=True).start()
serve(8443, True)
