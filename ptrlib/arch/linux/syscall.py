import functools
from ptrlib.arch.arm import bit_by_arch_arm, SyscallTableArm
from ptrlib.arch.intel import bit_by_arch_intel, SyscallTableIntel

try:
    cache = functools.cache
except AttributeError:
    cache = functools.lru_cache


class _SyscallTable(object):
    @cache
    def __getitem__(self, arch: str):
        # Intel series
        bits = bit_by_arch_intel(arch)
        if bits != -1:
            return SyscallTableIntel(bits)

        # ARM series
        bits = bit_by_arch_arm(arch)
        if bits != -1:
            return SyscallTableArm(bits)

        raise KeyError("Invalid architecture '{}'".format(arch))

    def __getattr__(self, arch: str):
        return self[arch]

syscall = _SyscallTable()
