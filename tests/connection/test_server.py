import os
import random
import threading
import time
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

    def test_tcp_server_timeout(self):
        """Test TCP server timeout
        """
        lock = True
        port = 8000 + random.randint(0, 2000)
        server = Server("localhost", port)

        data = os.urandom(16).hex()
        def serve():
            nonlocal lock
            conn = server.accept()
            while lock:
                pass
            conn.close_send()
            with self.assertRaises(TubeTimeout) as e:
                conn.recvline(timeout=0.5)
            self.assertEqual(e.exception.buffered, data.encode())

        th = threading.Thread(target=serve, daemon=True)
        th.start()

        cli = Socket("localhost", port)
        lock = False
        cli.close_recv()
        cli.send(data)

        th.join()

    def test_udp_server(self):
        """Test UDP server functionality
        """
        port = 12000 + random.randint(0, 2000)
        server = Server("localhost", port, udp=True)

        # 10 lines up, 10 lines back
        data = os.urandom(16 * 20).hex()

        def serve_udp():
            conn = server.accept()  # waits for first datagram
            # First 10 messages should be received from client
            for i in range(10):
                expected = data[i*32:(i+1)*32].encode()
                self.assertEqual(conn.recvline(), expected)
            # Send next 10 messages back to client
            for i in range(10, 20):
                conn.sendline(data[i*32:(i+1)*32])
                time.sleep(0.01)

        th = threading.Thread(target=serve_udp, daemon=True)
        th.start()

        cli = Socket("localhost", port, udp=True)
        # Send 10 messages
        for i in range(10):
            cli.sendline(data[i*32:(i+1)*32])
            time.sleep(0.01)
        # Receive 10 messages
        for i in range(10, 20):
            expected = data[i*32:(i+1)*32].encode()
            self.assertEqual(cli.recvline(), expected)

        th.join()

    def test_udp_server_accept_timeout(self):
        """Server.accept should timeout on UDP when no datagram arrives
        """
        port = 14000 + random.randint(0, 2000)
        server = Server("localhost", port, udp=True)
        with self.assertRaises(TimeoutError):
            _ = server.accept(timeout=0.2)
