"""This package provides some tests for Process feature.
"""
import os
import random
import unittest
from logging import FATAL, getLogger

from ptrlib import Process

_is_windows = os.name == 'nt'


class TestTubeDefer(unittest.TestCase):
    """Tests for Tube defer
    """
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)
        if _is_windows:
            self.skipTest("This test is intended for the Linux platform")

    def test_process(self):
        """Process defer tests
        """
        p = Process("./tests/test.bin/test_echo.x64")
        n = random.randint(10, 100)
        lines = [os.urandom(random.randint(1, 100)).hex() for _ in range(n)]
        leftover = os.urandom(random.randint(1, 100))
        for i in range(len(lines)):
            p.send(f"Line {i+1}: ")
        p.send(leftover)

        with p.defer_after():
            for line in lines:
                p.after(b": ").sendline(line)
            self.assertEqual(p.recvall(len(leftover)), leftover)

        for i, line in enumerate(lines):
            p.sendline(f"Line {i+1}: " + line)

        with p.defer_after():
            for line in lines:
                s = p.after(b": ").recvall(len(line) // 2)
                t = p.recvline()
                self.assertEqual(s, line[:len(line)//2].encode())
                self.assertEqual(t, line[len(line)//2:].encode())

    def test_nested_defer_after(self):
        """Nested `with defer_after()` should flush only at the outermost exit
        """
        p = Process("./tests/test.bin/test_echo.x64")

        # Count low-level recv calls to detect unexpected flushes
        recv_calls = {"n": 0}
        orig_recv_impl = p._recv_impl
        def wrapped_recv_impl(blocksize: int) -> bytes:
            recv_calls["n"] += 1
            return orig_recv_impl(blocksize)
        p._recv_impl = wrapped_recv_impl  # type: ignore[attr-defined]

        # Ensure the expected delimiter exists in the peer output (echo back)
        p.send(b"PROMPT: ")

        with p.defer_after():
            with p.defer_after():
                p.after(b": ").sendline(b"OK")  # `after` should be queued, not read yet

            # Inner exit must NOT flush
            self.assertEqual(recv_calls["n"], 0)

        # Outermost exit must flush queued `after`
        self.assertGreater(recv_calls["n"], 0)

        # After flushing `PROMPT: `, the remaining echoed line should be "OK\n"
        self.assertEqual(p.recvline(), b"OK")

    def test_after_is_deferred(self):
        """`after()` must not perform recv while inside defer_after()
        """
        p = Process("./tests/test.bin/test_echo.x64")

        recv_calls = {"n": 0}
        orig_recv_impl = p._recv_impl
        def wrapped_recv_impl(blocksize: int) -> bytes:
            recv_calls["n"] += 1
            return orig_recv_impl(blocksize)
        p._recv_impl = wrapped_recv_impl  # type: ignore[attr-defined]

        # Make sure delimiter already exists in the stream (echo back)
        p.send(b"X: ")

        with p.defer_after():
            # If `after` were NOT deferred, it would end up calling recv/recvuntil here.
            p.after(b": ").sendline(b"Y")
            self.assertEqual(recv_calls["n"], 0)

        # Exiting the context should flush (i.e., actually perform recv)
        self.assertGreater(recv_calls["n"], 0)
