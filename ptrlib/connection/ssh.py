"""This package provides SSH function.
"""
import shlex
import os
from typing import Optional
from ptrlib.arch.common import which
from .proc import Process


def SSH(host: str,
        port: int,
        username: str,
        password: Optional[str]=None,
        identity: Optional[str]=None,
        ssh_path: Optional[str]=None,
        expect_path: Optional[str]=None,
        option: str='',
        command: str=''):
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

    if ssh_path is None:
        ssh_path = which('ssh')
    if expect_path is None:
        expect_path = which('expect')

    if ssh_path is None or not os.path.isfile(ssh_path):
        raise FileNotFoundError(f"{ssh_path}: SSH not found")
    if expect_path is None or not os.path.isfile(expect_path):
        raise FileNotFoundError(f"{expect_path}: 'expect' not found")

    if identity is not None:
        option += f' -i {shlex.quote(identity)}'

    script = f'eval spawn {ssh_path} ' \
        f'-oStrictHostKeyChecking=no -oCheckHostIP=no ' \
        f'{shlex.quote(username)}@{shlex.quote(host)} '\
        f'-p{port} {option} {command}; '\
        f'interact; lassign [wait] pid spawnid err value; exit "$value"'

    proc = Process(
        [expect_path, '-c', script],
    )
    if identity is None:
        if password is None:
            raise ValueError("You must give either password or identity")
        proc.sendlineafter("password: ", password)

    return proc


__all__ = ['SSH']
