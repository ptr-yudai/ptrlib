import os
import unittest
from unittest import mock


class TestSSH(unittest.TestCase):
    def test_build_ssh_argv_order_and_flags(self):
        # Import here so the test suite works even if ssh isn't installed.
        from ptrlib.connection.ssh import _build_ssh_argv

        argv = _build_ssh_argv(
            host="example.com",
            username="user",
            port=2222,
            identity=None,
            ssh_path=os.path.abspath(__file__),  # any existing file; we only test argv ordering
            options=["-v"],
            command=None,
        )

        # Destination must come after options and '-p PORT'
        self.assertIn("user@example.com", argv)
        dest_i = argv.index("user@example.com")
        self.assertEqual(argv[dest_i - 2:dest_i], ["-p", "2222"])

        # Interactive sessions should request a TTY unless user disables it explicitly.
        self.assertIn("-tt", argv)

    def test_build_ssh_argv_command_appended_at_end(self):
        from ptrlib.connection.ssh import _build_ssh_argv

        argv = _build_ssh_argv(
            host="example.com",
            username="user",
            port=22,
            ssh_path=os.path.abspath(__file__),
            options=["-oBatchMode=yes"],
            command="id",
        )

        self.assertEqual(argv[-1], "id")
        self.assertNotIn("-tt", argv)  # command => not forced

    @unittest.skipUnless(os.name == "nt", "Windows-only behavior")
    def test_ssh_password_windows_raises(self):
        from ptrlib.connection.ssh import SSH

        # Should not raise immediately; password is provided via SSH_ASKPASS on Windows.
        # We mock Process to avoid trying to execute a real ssh binary in CI.
        class DummyProc:
            def __init__(self, argv, env=None, **_kwargs):
                self.argv = argv
                self.env = env
                self.prompt = ""
            def close(self):
                return

        with mock.patch("ptrlib.connection.ssh.Process", DummyProc):
            ssh = SSH(
                "example.com",
                "user",
                password="pw",
                # Any existing file passes isfile() check and won't be executed due to mocking.
                ssh_path=os.path.abspath(__file__),
            )
            self.assertIsNotNone(getattr(ssh, "env", None))
            self.assertIn("SSH_ASKPASS", ssh.env)
            self.assertIn("PTRLIB_SSH_PASSWORD", ssh.env)

    @unittest.skipUnless(os.name == "nt", "Windows-only behavior")
    def test_ssh_no_password_windows_forces_batchmode(self):
        from ptrlib.connection.ssh import SSH

        class DummyProc:
            def __init__(self, argv, env=None, **_kwargs):
                self.argv = argv
                self.env = env
                self.prompt = ""
            def recv(self, *_args, **_kwargs):
                # no output
                return b""
            def _is_alive_impl(self):
                return True
            def close(self):
                return

        with mock.patch("ptrlib.connection.ssh.Process", DummyProc):
            ssh = SSH(
                "example.com",
                "user",
                ssh_path=os.path.abspath(__file__),
            )
            # Ensure we set BatchMode=yes to prevent hanging on password prompts.
            self.assertTrue(any(a.startswith("-oBatchMode=yes") for a in ssh.argv))

