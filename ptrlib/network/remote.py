"""Remote connection class"""
import socket

class Socket(object):
    """Establish a connect to a server, receive and send data

    Usage:
        sock = Socket('localhost', 4000)
        sock.recvuntil('Name: ')
        sock.sendline('John')
        data = sock.recvline()
    """
    def __init__(self, host, port):
        """Initialize and reset this instance.

        A connection will be established in this constructor.
        """
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.timeout = None

    def recv(self, size, timeout=None):
        """Receive data from the server
        
        This function returns `size` bytes data received from the server.
        The function will be interrupted and returns None when `timeout` seconds passes.
        """
        # Set timeout
        if timeout is None:
            self.sock.settimeout(self.timeout)
        else:
            self.sock.settimeout(timeout)
        # Receive
        try:
            data = self.sock.recv(size)
        except socket.timeout:
            data = None
        finally:
            # Set timeout to the default value
            self.settimeout(self.timeout)
        if len(data) == 0:
            return None
        return data
        
    def recvline(self, timeout=None):
        """Receive a line of data from the server

        This function returns a line of data received from the server.
        The function will be interrupted and returns None when `timeout` seconds passes.
        """
        data = ''
        while True:
            c = self.recv(1, timeout=timeout)
            if c is None:
                return None
            elif c == '\n' or c == '\r':
                break
            data += c
        return data

    def recvuntil(self, needle, timeout=None):
        """Receive data from the server until `needle` appears in the data
        
        This function returns data received from the server.
        The data ends with `needle`.
        If `needle` doesn't appear in the received data or `timeout` seconds passes,
        this function will return None.
        """
        length = len(needle)
        if length == 0:
            raise ValueError("The length of `needle` must be larger than zero")
        data = ''
        while True:
            c = self.recv(1, timeout=timeout)
            if c is None:
                return None
            data += c
            if data.endswith(needle):
                break
        return data

    def recvall(self, size=4096, timeout=None):
        data = ''
        if size <= 0:
            raise ValueError("The value of `size` must be larger than zero")
        while True:
            packet = self.recv(size, timeout=timeout)
            if packet is None:
                break
            data += packet
        return data

    def send(self, data):
        """Send data to the server

        This function sends data to the server.
        """
        self.sock.send(data)

    def sendline(self, data):
        """Send data with newline to the server

        This function sends data with a newline appended.
        """
        self.send(data + '\n')

    def settimeout(self, second):
        self.timeout = second
        
    def gettimeout(self):
        return self.timeout

    def close(self):
        self.sock.close()
