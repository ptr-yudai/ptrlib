# coding: utf-8
from logging import getLogger
from ptrlib.util.encoding import *
from ptrlib.pwn.tube import *
from ptrlib.pwn.winproc import *
import errno
import select
import os
import subprocess
import time

_is_windows = os.name == 'nt'
if not _is_windows:
    import fcntl
    import pty
    import tty

logger = getLogger(__name__)

def Process(*args, **kwargs):
    if _is_windows:
        return WinProcess(*args, **kwargs)
    else:
        return UnixProcess(*args, **kwargs)

class UnixProcess(Tube):
    def __init__(self, args, env=None, cwd=None, timeout=None):
        """Create a process

        Create a new process and make a pipe.

        Args:
            args (list): The arguments to pass
            env (list) : The environment variables

        Returns:
            Process: ``Process`` instance.
        """
        assert not _is_windows
        super().__init__()

        if isinstance(args, list):
            self.args = args
            self.filepath = args[0]
        else:
            self.args = [args]
            self.filepath = args
        self.env = env
        self.default_timeout = timeout
        self.timeout = self.default_timeout
        self.reservoir = b''
        self.proc = None
        self.returncode = None

        # Open pty on Unix
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
        if master is not None:
            self.proc.stdout = os.fdopen(os.dup(master), 'r+b', 0)
            os.close(master)

        # Set in non-blocking mode
        fd = self.proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        logger.info("Successfully created new process (PID={})".format(self.proc.pid))

    def _settimeout(self, timeout):
        if timeout is None:
            self.timeout = self.default_timeout
        elif timeout > 0:
            self.timeout = timeout

    def _socket(self):
        return self.proc

    def _poll(self):
        if self.proc is None:
            return False

        # Check if the process exits
        self.proc.poll()
        returncode = self.proc.returncode
        if returncode is not None and self.returncode is None:
            self.returncode = returncode
            logger.error(
                "Process '{}' stopped with exit code {} (PID={})".format(
                    self.filepath, returncode, self.proc.pid
                ))
        return returncode

    def is_alive(self):
        """Check if the process is alive"""
        return self._poll() is None

    def _can_recv(self):
        """Check if receivable"""
        if self.proc is None:
            return False

        try:
            r = select.select(
                [self.proc.stdout], [], [], self.timeout
            )
            if r == ([], [], []):
                raise TimeoutError("Receive timeout")
            else:
                # assert r == ([self.proc.stdout], [], [])
                return True
        except TimeoutError as e:
            raise e from None
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
            return b''

        if size <= len(self.reservoir):
            # Use the buffer
            data = self.reservoir[:size]
            self.reservoir = self.reservoir[size:]
            return data

        if not self._can_recv():
            return b''

        try:
            data = self.proc.stdout.read(size)
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

    def send(self, data):
        """Send raw data

        Send raw data through the socket

        Args:
            data (bytes) : Data to send
        """
        self._poll()
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
            logger.info("'{0}' killed".format(self.filepath))

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

    def wait(self):
        """Wait until the process dies

        Wait until the process exits and get the status code.

        Returns:
            code (int): Status code of the process
        """
        while self.is_alive():
            time.sleep(0.1)
        return self.returncode

    def __del__(self):
        self.close()

# alias
process = Process
