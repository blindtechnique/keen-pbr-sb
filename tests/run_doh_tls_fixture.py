"""Offline HTTPS fixture. Keys/certificates exist only in a disposable tempdir."""
import http.server
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        query = bytearray(self.rfile.read(int(self.headers["Content-Length"])))
        if len(query) < 12 or self.headers.get("Content-Type") != "application/dns-message":
            self.send_error(400)
            return
        query[2] |= 0x80
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(query)))
        self.end_headers()
        self.wfile.write(query)


def main():
    with tempfile.TemporaryDirectory(prefix="kpbr-doh-tls-") as tmp:
        cert = str(Path(tmp) / "cert.pem")
        key = str(Path(tmp) / "key.pem")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key, "-out", cert, "-days", "1",
            "-subj", "/CN=doh-fixture.example",
            "-addext", "subjectAltName=DNS:doh-fixture.example",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        env = dict(os.environ, KPBR_TEST_DOH_CA=cert,
                   KPBR_TEST_DOH_PORT=str(server.server_address[1]),
                   HTTPS_PROXY="http://127.0.0.1:1", ALL_PROXY="http://127.0.0.1:1",
                   https_proxy="http://127.0.0.1:1", all_proxy="http://127.0.0.1:1",
                   NO_PROXY="", no_proxy="")
        try:
            return subprocess.run(sys.argv[1:], env=env, check=False).returncode
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    sys.exit(main())
