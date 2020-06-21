# coding: utf-8
from logging import getLogger
from ptrlib.util.encoding import *
from ptrlib.pwn.tube import *
import errno
import select
import fcntl
import os
import pty
import subprocess
import tty

logger = getLogger(__name__)

class Process(Tube):
    def __init__(self, args, env=None, cwd=None, timeout=None):
        """Create a process

        Create a new process and make a pipe.

        Args:
            args (list): The arguments to pass
            env (list) : The environment variables

        Returns:
            Process: ``Process`` instance.
        """
        super().__init__()

        if isinstance(args, list):
            self.args = args
            self.filepath = args[0]
        else:
            self.args = [args]
            self.filepath = args
        self.env = env
        self.timeout = timeout
        self.temp_timeout = None
        self.reservoir = b''
        self.proc = None

        # Open pty
        master, self.slave = pty.openpty()
        tty.setraw(master)
        tty.setraw(self.slave)

        # Create a new process
        try:
            self.proc = subprocess.Popen(
                self.args,
                cwd = cwd,
                env = self.env,
                shell = False,
                stdout=self.slave,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE
            )
        except FileNotFoundError:
            logger.warning("Executable not found: '{0}'".format(self.filepath))
            return

        # Duplicate master
        self.proc.stdout = os.fdopen(os.dup(master), 'r+b', 0)
        os.close(master)

        # Set in non-blocking mode
        fd = self.proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        logger.info("Successfully created new process (PID={})".format(self.proc.pid))

    def _settimeout(self, timeout):
        if timeout is None:
            self.temp_timeout = self.timeout
        else:
            self.temp_timeout = timeout

    def _socket(self):
        return self.proc

    def _poll(self):
        if self.proc is None:
            return False

        self.proc.poll()
        returncode = self.proc.returncode
        if returncode is not None:
            logger.error(
                "Process '{}' stopped with exit code {} (PID={})".format(
                    self.filepath, returncode, self.proc.pid
                ))
            self.proc = None
        return returncode

    def _is_alive(self):
        return self._poll() is None

    def _can_recv(self):
        if self.proc is None:
            return False

        try:
            return select.select([self.proc.stdout], [], [], self.temp_timeout) == ([self.proc.stdout], [], [])
        except select.error as v:
            if v[0] == errno.EINTR:
                return False

    def _recv(self, size=4096, timeout=None):
        """Receive raw data

        Receive raw data of maximum `size` bytes length through the pipe.

        Args:
            size    (int): The data size to receive
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        self._settimeout(timeout)
        if size <= 0:
            logger.error("`size` must be larger than 0")
            return None

        if size <= len(self.reservoir):
            # Use the buffer
            data = self.reservoir[:size]
            self.reservoir = self.reservoir[size:]
            return data

        if not self._can_recv():
            return b''

        try:
            data = self.proc.stdout.read()
            self.reservoir += data
        except subprocess.TimeoutExpired:
            logger.error("Timeout")
            return None

        self._poll() # poll after received all data

        if len(self.reservoir) == 0:
            # No data received
            data = None
        elif len(self.reservoir) >= size:
            # Too much data received
            data = self.reservoir[:size]
            self.reservoir = self.reservoir[size:]
        else:
            # Too little data received
            data = self.reservoir
            self.reservoir = b''
        return data

    def send(self, data, timeout=None):
        """Send raw data

        Send raw data through the socket

        Args:
            data (bytes) : Data to send
            timeout (int): Timeout (in second)
        """
        self._settimeout(timeout)
        if isinstance(data, str):
            data = str2bytes(data)

        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except IOError:
            logger.warning("Broken pipe")

    def close(self):
        """Close the socket

        Close the socket.
        This method is called from the destructor.
        """
        if self.proc:
            os.close(self.slave)
            self.proc.kill()
            self.proc.wait()
            self.proc = None
            logger.info("close: '{0}' killed".format(self.filepath))

    def shutdown(self, target):
        """Kill one connection

        Close send/recv pipe.

        Args:
            target (str): Connection to close (`send` or `recv`)
        """
        if target in ['write', 'send', 'stdin']:
            self.proc.stdin.close()

        elif target in ['read', 'recv', 'stdout', 'stderr']:
            self.proc.stdout.close()

        else:
            logger.error("You must specify `send` or `recv` as target.")

    def __del__(self):
        self.close()
