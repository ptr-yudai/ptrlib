"""Linux constants grouped by category.

Examples:
    from ptrlib.os import linux
    linux.consts.O_RDONLY
    linux.consts.socket.AF_INET
    linux.consts.ptrace.PTRACE_ATTACH
"""

from . import socket as socket_consts
from . import memory as memory_consts
from . import signal as signal_consts
from . import file as file_consts
from . import process as process_consts
from . import personality as personality_consts
from . import ptrace as ptrace_consts

socket = socket_consts
memory = memory_consts
signal = signal_consts
file = file_consts
process = process_consts
personality = personality_consts
ptrace = ptrace_consts

from .socket import *
from .memory import *
from .signal import *
from .file import *
from .process import *
from .personality import *
from .ptrace import *

__all__ = (
    socket_consts.__all__
    + memory_consts.__all__
    + signal_consts.__all__
    + file_consts.__all__
    + process_consts.__all__
    + personality_consts.__all__
    + ptrace_consts.__all__
)
