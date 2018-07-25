#!/usr/bin/env python
import socket

def main():
    """ Listen for a single connection on port 3001. Accept the connection
        and then immediately close the socket. Used to ensure that we are
        able to portably suppress SIGPIPE inside of libndt. """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 3001))
    sock.listen(1)
    conn, _ = sock.accept()
    conn.close()

if __name__ == "__main__":
    main()
