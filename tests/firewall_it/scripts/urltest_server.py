#!/usr/bin/env python3
import argparse
import http.server
import socketserver
import time


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/fast":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"fast\n")
            return

        if self.path == "/slow":
            time.sleep(0.25)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"slow\n")
            return

        if self.path == "/fail":
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"fail\n")
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, fmt, *args):
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument(
        "--ready-fifo",
        default=None,
        help="FIFO to signal once the listening socket is bound, so a caller "
        "can block on readiness instead of guessing with a sleep",
    )
    args = parser.parse_args()

    with socketserver.TCPServer((args.host, args.port), Handler) as httpd:
        # TCPServer's constructor has already run bind() and listen(), so any
        # connection made from this point on is queued in the backlog and will
        # be answered once serve_forever() starts. Signalling here is therefore
        # a genuine happens-before edge for the probe, not an approximation.
        if args.ready_fifo:
            # Opening for write blocks until the reader opens its end, and the
            # reader sees EOF when this close() runs.
            with open(args.ready_fifo, "w") as ready:
                ready.write("ready\n")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
