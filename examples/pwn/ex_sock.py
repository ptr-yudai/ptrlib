#!/usr/bin/env python
from ptrlib import *

# establish connection
sock = Socket("www.example.com", 80)

# send request
request  = b'GET / HTTP/1.1\r\n'
request += b'Host: www.example.com\r\n\r\n'
sock.send(request)

# receive request until Content-Length
sock.recvuntil("Content-Length: ")

# receive a line
l = int(sock.recvline())
print("Content-Length = {}".format(l))

# close connection
sock.close()

# establish connection
sock = Socket("www.example.com", 80)

# send request
request  = b'GET / HTTP/1.1\r\n'
request += b'Host: www.example.com\r\n\r\n'
sock.send(request)
print("Content-Length = {}".format(sock.recvlineafter('Content-Length: ')))

# close connection
sock.close()
