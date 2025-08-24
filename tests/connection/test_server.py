import os
import random
import threading
import unittest
from logging import getLogger, FATAL
from ptrlib import Socket, Server, TubeTimeout


class TestServer(unittest.TestCase):
    """Tests for Server
    """
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_tcp_server(self):
        """Test TCP server functionality
        """
        port = 8000 + random.randint(0, 2000)
        server = Server("localhost", port)

        data = os.urandom(16 * 20).hex()

        def serve():
            conn = server.accept()
            for i in range(10):
                self.assertTrue(conn.recvline(), data[i*32:(i+1)*32].encode())
            for i in range(10, 20):
                conn.sendline(data[i*32:(i+1)*32])

        th1 = threading.Thread(target=serve, daemon=True)
        th2 = threading.Thread(target=serve, daemon=True)
        th1.start()
        th2.start()

        cli1 = Socket("localhost", port)
        cli2 = Socket("localhost", port)
        for i in range(10):
            cli1.sendline(data[i*32:(i+1)*32])
            cli2.sendline(data[i*32:(i+1)*32])
        for i in range(10, 20):
            self.assertTrue(cli1.recvline(), data[i*32:(i+1)*32].encode())
            self.assertTrue(cli2.recvline(), data[i*32:(i+1)*32].encode())

        th1.join()
        th2.join()
