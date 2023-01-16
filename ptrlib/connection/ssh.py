# coding: utf-8
import shlex
import os
from ptrlib.binary.encoding import *
from ptrlib.arch.common import which
from .proc import *

if os.name == 'nt':
    _is_windows = True
else:
    _is_windows = False


def SSH(host: str, port: int, username: str,
        password: Optional[str]=None, identity: Optional[str]=None,
        ssh_path: Optional[str]=None, expect_path: Optional[str]=None,
        option: str='', command: str=''):
    """Create an SSH shell

    Create a new process to connect to SSH server

    Args:
        host (str)    : SSH hostname
        port (int)    : SSH port
        username (str): SSH username
        password (str): SSH password
        identity (str): Path of identity file
        option (str)  : Parameters to pass to SSH
        command (str) : Initial command to execute on remote

    Returns:
        Process: ``Process`` instance.
    """
    assert isinstance(port, int)
    if password is None and identity is None:
        raise ValueError("You must give either password or identity")

    if ssh_path is None:
        ssh_path = which('ssh')
    if expect_path is None:
        expect_path = which('expect')

    if not os.path.isfile(ssh_path):
        raise FileNotFoundError("{}: SSH not found".format(ssh_path))
    if not os.path.isfile(expect_path):
        raise FileNotFoundError("{}: 'expect' not found".format(expect_path))

    if identity is not None:
        option += ' -i {}'.format(shlex.quote(identity))

    script = 'eval spawn {} -oStrictHostKeyChecking=no -oCheckHostIP=no {}@{} -p{} {} {}; interact; lassign [wait] pid spawnid err value; exit "$value"'.format(
        ssh_path,
        shlex.quote(username),
        shlex.quote(host),
        port,
        option,
        command
    )

    proc = Process(
        [expect_path, '-c', script],
    )
    if identity is None:
        proc.sendlineafter("password: ", password)

    return proc
