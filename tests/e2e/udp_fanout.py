"""Forward every UDP datagram received on LISTEN to all TARGET ports on 127.0.0.1.

Usage: udp_fanout.py LISTEN:TARGET[,TARGET...] [...]
Both collectors therefore see byte-identical datagrams at the same moment.
"""
import selectors
import socket
import sys

sel = selectors.DefaultSelector()
out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for spec in sys.argv[1:]:
    listen, targets = spec.split(":")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    s.bind(("127.0.0.1", int(listen)))
    sel.register(s, selectors.EVENT_READ, [int(t) for t in targets.split(",")])
while True:
    for key, _ in sel.select():
        data = key.fileobj.recv(65536)
        for port in key.data:
            out.sendto(data, ("127.0.0.1", port))
