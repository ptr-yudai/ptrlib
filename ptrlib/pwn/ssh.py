# coding: utf-8
import shlex
import os
from logging import getLogger
from ptrlib.util.encoding import *
from ptrlib.pwn.proc import *

def SSH(host, port, username,
        password=None, identity=None,
        ssh_path=None, expect_path=None,
        option=''):
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

    if ssh_path is None:
        ssh_path = '/usr/bin/ssh'
    if expect_path is None:
        expect_path = '/usr/bin/expect'

    if not os.path.isfile(ssh_path):
        raise FileNotFoundError("{}: SSH not found".format(ssh_path))
    if not os.path.isfile(expect_path):
        raise FileNotFoundError("{}: 'expect' not found".format(expect_path))

    if identity is not None:
        option += ' -i {}'.format(shlex.quote(identity))

    script = 'eval spawn {} -oStrictHostKeyChecking=no -oCheckHostIP=no {}@{} -p{} {}; interact'.format(
        ssh_path,
        shlex.quote(username),
        shlex.quote(host),
        port,
        option
    )

    proc = Process(
        [expect_path, '-c', script],
    )
    if identity is None:
        proc.sendlineafter("password: ", password)

    return proc
