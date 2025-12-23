"""This package provides SSH function.

Notes
-----
This module intentionally spawns the system ``ssh`` client instead of implementing
the SSH protocol in Python.

Historically this wrapper could "hang" in two common cases:

1) Wrong argument order: ``ssh`` options (e.g. ``-p``) must appear *before* the
   destination ``user@host``. Placing options after the destination makes them
   part of the remote command, and the client would try to connect to the default
   port (22) instead of the requested one.
2) No TTY: when stdin is not a TTY, OpenSSH does not allocate a remote PTY by
   default. An interactive shell then produces no prompt and appears to hang.
   On POSIX we can solve this by spawning ``ssh`` under a PTY; additionally we
   request a TTY with ``-tt`` for interactive sessions.
"""
import os
import re
import contextlib
import sys
import tempfile
from pathlib import Path
from ptrlib.os import which
from .proc import Process


def _build_ssh_argv(host: str,
                    username: str,
                    *,
                    port: int = 22,
                    identity: str | None = None,
                    ssh_path: str | None = None,
                    options: list[str] | None = None,
                    command: str | None = None) -> list[str]:
    """Build argv for the system ssh client.

    This is split out for testability.
    """
    assert isinstance(port, int)

    if ssh_path is None:
        ssh_path = which('ssh')
    if ssh_path is None or not os.path.isfile(ssh_path):
        raise FileNotFoundError(f"{ssh_path}: SSH not found")

    # Copy to avoid mutating caller-provided list.
    user_options: list[str] = list(options or [])

    # Default options (can be overridden by user_options if needed).
    # Use os.devnull so this works on both POSIX and Windows (NUL).
    base_options: list[str] = [
        '-oStrictHostKeyChecking=no',
        '-oCheckHostIP=no',
        # Reduce noisy banners like "Permanently added ..." which can confuse users
        # into thinking the connection is stuck.
        '-oLogLevel=ERROR',
        f'-oUserKnownHostsFile={os.devnull}',
        f'-oGlobalKnownHostsFile={os.devnull}',
    ]

    if identity is not None:
        base_options += ['-i', os.path.realpath(os.path.expanduser(identity))]

    # If this is an interactive session (no remote command), request a TTY.
    # This avoids the "no prompt" behavior when ssh's stdin is a pipe.
    if not command:
        has_tty_flag = any(opt in ('-t', '-tt', '-T') for opt in user_options)
        if not has_tty_flag:
            base_options.append('-tt')

    argv: list[str] = [
        ssh_path,
        *base_options,
        *user_options,
        '-p', str(port),
        f'{username}@{host}',
    ]

    # Append remote command at the end (ssh syntax: destination [command]).
    if command:
        argv.append(command)

    return argv


def _ensure_windows_askpass_cmd() -> str:
    """Create a minimal SSH_ASKPASS helper for Windows and return its path.

    OpenSSH reads passwords from the controlling console/TTY, not stdin.
    When our child process has no console (typical for piped subprocesses),
    providing a password via stdin will hang.

    On Windows, OpenSSH supports SSH_ASKPASS. We provide a tiny .cmd wrapper
    which prints the password from an env var.
    """
    # Use a stable path so we don't leak many temp files.
    path = Path(tempfile.gettempdir()) / "ptrlib-ssh-askpass.cmd"

    # This uses env var PTRLIB_PYTHON to avoid hardcoding a python path.
    # The prompt argument passed by ssh is ignored.
    content = (
        "@echo off\r\n"
        "\"%PTRLIB_PYTHON%\" -c \"import os,sys; "
        "sys.stdout.write(os.environ.get('PTRLIB_SSH_PASSWORD',''))\"\r\n"
    )

    try:
        if path.is_file():
            try:
                if path.read_text(encoding="utf-8", errors="ignore") == content:
                    return str(path)
            except Exception:
                # Rewrite on any read/decode issue.
                pass
        path.write_text(content, encoding="utf-8")
    except Exception:
        # Fall back to a per-process file name.
        path = Path(tempfile.gettempdir()) / f"ptrlib-ssh-askpass-{os.getpid()}.cmd"
        path.write_text(content, encoding="utf-8")

    return str(path)


def _ensure_posix_askpass_sh() -> str:
    """Create a minimal SSH_ASKPASS helper for POSIX and return its path.

    OpenSSH can read passwords via an external helper specified by SSH_ASKPASS.
    We provide a tiny, non-interactive helper that prints the password from an
    environment variable. This avoids fragile prompt parsing and works even
    when stdin is not a TTY or when ssh suppresses prompts.
    """
    path = Path(tempfile.gettempdir()) / "ptrlib-ssh-askpass.sh"

    content = (
        "#!/bin/sh\n"
        "# ptrlib askpass helper (POSIX)\n"
        "# $1 is the prompt (ignored).\n"
        "# Print the password from $PTRLIB_SSH_PASSWORD without a trailing newline.\n"
        "if [ -n \"$PTRLIB_SSH_PASSWORD\" ]; then\n"
        "  printf '%s' \"$PTRLIB_SSH_PASSWORD\"\n"
        "fi\n"
    )

    try:
        if path.is_file():
            try:
                if path.read_text(encoding="utf-8", errors="ignore") == content:
                    # Ensure executable bit is set
                    try:
                        os.chmod(path, 0o700)
                    except Exception:
                        pass
                    return str(path)
            except Exception:
                pass
        path.write_text(content, encoding="utf-8")
        try:
            os.chmod(path, 0o700)
        except Exception:
            pass
    except Exception:
        # Fallback to a per-process path
        path = Path(tempfile.gettempdir()) / f"ptrlib-ssh-askpass-{os.getpid()}.sh"
        path.write_text(content, encoding="utf-8")
        with contextlib.suppress(Exception):
            os.chmod(path, 0o700)

    return str(path)


def _ensure_ssh_option(options: list[str], key: str, value: str) -> None:
    """Append -oKey=Value if the key isn't already present."""
    prefix = f"-o{key}="
    if any(isinstance(o, str) and o.startswith(prefix) for o in options):
        return
    options.append(prefix + value)


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
    # Copy options so we never mutate the caller's list.
    opt: list[str] = list(options or [])

    env = None

    # Windows note:
    # - OpenSSH reads passwords from the console, not stdin.
    # - Our WinProcess is pipe-based; if ssh decides it needs a password prompt,
    #   it will print a prompt but ignore bytes we write to stdin -> apparent hang.
    # Therefore, on Windows we either:
    #   - use SSH_ASKPASS (when password is provided), or
    #   - force BatchMode=yes (when password is NOT provided) so ssh fails fast
    #     instead of prompting.
    if os.name == 'nt' and password is None and identity is None:
        # Allow agent/publickey auth; disable any password prompt to avoid hangs.
        _ensure_ssh_option(opt, "BatchMode", "yes")
        _ensure_ssh_option(opt, "NumberOfPasswordPrompts", "0")
        # Prefer non-interactive methods.
        _ensure_ssh_option(opt, "PreferredAuthentications", "publickey")
    if password is not None:
        # Encourage password auth and avoid repeated prompts.
        _ensure_ssh_option(opt, "BatchMode", "no")
        _ensure_ssh_option(opt, "NumberOfPasswordPrompts", "1")
        _ensure_ssh_option(opt, "PreferredAuthentications", "password,keyboard-interactive")

        if os.name == 'nt':
            # Use SSH_ASKPASS on Windows to supply the password.
            askpass = _ensure_windows_askpass_cmd()
            env = os.environ.copy()
            env["PTRLIB_PYTHON"] = sys.executable
            env["PTRLIB_SSH_PASSWORD"] = password
            env["SSH_ASKPASS"] = askpass
            env["SSH_ASKPASS_REQUIRE"] = "force"
            # Some builds still require DISPLAY to be non-empty to invoke askpass.
            env.setdefault("DISPLAY", "1")
        else:
            # On POSIX, prefer SSH_ASKPASS to avoid fragile prompt parsing and to
            # work even when OpenSSH chooses not to echo prompts to the PTY.
            askpass = _ensure_posix_askpass_sh()
            env = os.environ.copy()
            env["PTRLIB_SSH_PASSWORD"] = password
            # Ensure no controlling TTY to force askpass on older OpenSSH builds
            env["PTRLIB_START_NEW_SESSION"] = "1"
            env["SSH_ASKPASS"] = askpass
            env["SSH_ASKPASS_REQUIRE"] = "force"
            # Historically OpenSSH only invoked askpass when DISPLAY was set; keep it.
            env.setdefault("DISPLAY", "1")

    argv = _build_ssh_argv(
        host,
        username,
        port=port,
        identity=identity,
        ssh_path=ssh_path,
        options=opt,
        command=command,
    )

    # On POSIX, use a PTY for interactive shells when no programmatic password is used.
    # If a password is provided, prefer pipes (no controlling TTY) so SSH_ASKPASS is
    # reliably used even on older OpenSSH that ignore SSH_ASKPASS_REQUIRE=force.
    if os.name != 'nt':
        use_local_pty = (password is None) and (not command)
        sess = Process(argv, use_tty=use_local_pty, env=env)
    else:
        sess = Process(argv, env=env)

    sess.prompt = ""

    if password is not None and os.name != 'nt':
        # If we're using askpass, prompts won't appear on the TTY. Skip prompt parsing.
        using_askpass = (env is not None) and (env.get("SSH_ASKPASS_REQUIRE") == "force")
        if not using_askpass:
            # Handle common prompts robustly (case-insensitive, includes hostkey prompt).
            hostkey_re = re.compile(br"(?i)are you sure you want to continue connecting")
            password_re = re.compile(br"(?i)password:\s*")
            denied_re = re.compile(br"(?i)permission denied")

            # Best-effort prompt dance: accept host key prompt, then send password.
            # If nothing matches within a short time, continue and let the user drive.
            for _ in range(3):
                with contextlib.suppress(Exception):
                    m = sess.recvregex([hostkey_re, password_re, denied_re], timeout=10)
                    if m.re is hostkey_re:
                        sess.sendline("yes")
                        continue
                    if m.re is password_re:
                        sess.sendline(password)
                        break
                    if m.re is denied_re:
                        raise PermissionError("SSH authentication failed (Permission denied)")

    # Windows: if we forced BatchMode (password=None), fail fast on auth errors.
    if os.name == 'nt' and password is None:
        denied_re = re.compile(br"(?i)permission denied")
        # Drain a small amount of early output; if the process exits due to auth,
        # raise a clear exception instead of letting `.interactive()` appear to hang.
        buf = bytearray()
        for _ in range(10):
            with contextlib.suppress(Exception):
                buf += sess.recv(4096, timeout=0.2)
            # If we already saw denial, stop early.
            if denied_re.search(buf):
                break
            # If the process is still alive and no denial yet, likely authenticated.
            with contextlib.suppress(Exception):
                if sess._is_alive_impl():
                    # Auth not denied yet; continue probing a bit.
                    pass

        if denied_re.search(buf):
            with contextlib.suppress(Exception):
                sess.close()
            raise PermissionError(
                "SSH authentication failed (Permission denied). On Windows, ptrlib cannot "
                "do an interactive password prompt via stdin; pass `password=` or `identity=` "
                "or use SSH agent/publickey auth."
            )

    return sess


__all__ = ['SSH']
