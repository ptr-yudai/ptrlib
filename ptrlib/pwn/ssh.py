# coding: utf-8
import shlex
import os
from logging import getLogger
from ptrlib.util.encoding import *
from ptrlib.pwn.proc import *

def SSH(host, port, username, password=None, identity=None, option=''):
    """Create an SSH shell

    Create a new process to connect to SSH server

    Args:
        host (str)    : SSH hostname
        port (int)    : SSH port
        username (str): SSH username
        password (str): SSH password
        identity (str): Path of identity file
        option (str)  : Parameters to pass to SSH

    Returns:
        Process: ``Process`` instance.
    """
    assert isinstance(port, int)
    if password is None and identity is None:
        raise ValueError("You must give either password or identity")

    if not os.path.isfile('/usr/bin/expect'):
        raise FileNotFoundError("'/usr/bin/expect' not found")

    if identity is not None:
        option += ' -i {}'.format(shlex.quote(identity))

    script = 'eval spawn ssh -oStrictHostKeyChecking=no -oCheckHostIP=no {}@{} -p{} {}; interact'.format(
        shlex.quote(username),
        shlex.quote(host),
        port,
        option
    )

    proc = Process(
        ["/usr/bin/expect", "-c", script],
    )
    if identity is None:
        proc.sendlineafter("password: ", password)

    return proc
