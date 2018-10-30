"""
    Python 3 webserver which supports IPv6
    original from:
        https://gist.github.com/akorobov/7903307

    Pseudo path of /ip will report client IP address back to client,
        otherwise, shows directory index
    Modified to work under python3 by Craig Miller 23 June 2017
    Version 0.94
"""

import socket
from http.server import HTTPServer, SimpleHTTPRequestHandler
import signal
import os

# port webserver listens to
listen_port = 80

# signal handlder for SIGINT
def sigint_handler(signal, frame):
    shutdown_requested = True
    print("\nCaught SIGINT, dying")
    os._exit(0)

# register SIGINT signal handler
signal.signal(signal.SIGINT, sigint_handler)

class MyHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # if path is /ip then print client IP address (v4 or v6)
        if self.path == '/ip':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            answer = 'Your IP address is ' + self.client_address[0]
            # convert string 'answer' to bytes for buffer output
            self.wfile.write(str.encode(answer))
            return
        else:
            return SimpleHTTPRequestHandler.do_GET(self)

class HTTPServerV6(HTTPServer):
    address_family = socket.AF_INET6

def main():
    global server
    server = HTTPServerV6(('::', listen_port), MyHandler)
    print('Listening on port:' + str(listen_port))
    server.serve_forever()
    os._exit(0)


if __name__ == '__main__':
    main()

