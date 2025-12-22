"""This package provides SSH function.
"""
import os
from ptrlib.os import which
from .proc import Process


def SSH(host: str,
        username: str,
        *,
        port: int = 22,
        password: str | None = None,
        identity: str | None = None,
        ssh_path: str | None = None,
        options: list[str] | None = None,
        command: str | None = None):
    """Create an SSH shell

    Create a new process to connect to SSH server

    Args:
        host       : SSH hostname
        port       : SSH port
        username   : SSH username
        password   : SSH password
        identity   : Path of identity file
        options    : Parameters to pass to SSH
        command    : Initial command to execute on remote

    Returns:
        Process: ``Process`` instance.

    Raises:
        FileNotFoundError: If SSH executable is not found.
    """
    assert isinstance(port, int)
    # Allow agent-based auth when neither password nor identity is provided.
    if ssh_path is None:
        ssh_path = which('ssh')
    if ssh_path is None or not os.path.isfile(ssh_path):
        raise FileNotFoundError(f"{ssh_path}: SSH not found")
    if options is None:
        options = []

    if identity is not None:
        options += ['-i', os.path.realpath(os.path.expanduser(identity))]

    argv: list[str] = [
        ssh_path,
        '-oStrictHostKeyChecking=no', '-oCheckHostIP=no',
        f'{username}@{host}',
        '-p', str(port),
        *options,
    ]
    # Only append command if provided (avoid passing an empty argument which
    # would make ssh execute an empty remote command and close immediately).
    if command:
        argv.append(command)

    sess = Process(argv)
    sess.prompt = ""
    if password is not None:
        sess.sendlineafter("password: ", password)
    return sess


__all__ = ['SSH']
