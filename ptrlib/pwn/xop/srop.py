"""This package provides some utilities for sigreturn oriented programming.
"""
from typing import Optional
from ptrlib.types import PtrlibArchT
from ptrlib.binary.packing.pack import p64
from ptrlib.binary.packing.flat import flat


class SROP:
    """Craft payload for SROP (sigreturn oriented programming).

    Examples:
        .. code-block:: python

            srop = SROP('intel')
            print(srop.payload)
    """
    def __init__(self, arch: Optional[PtrlibArchT]=None, **kwargs: int):
        if arch is None:
            # TODO: Infer architecture
            pass

        if arch == 'intel':
            self._srop = SROPx64(**kwargs)

        else:
            raise NotImplementedError(f"Not supported for {arch}")

    @property
    def payload(self) -> bytes:
        """Get SROP payload in bytes.
        """
        return self._srop.payload


class SROPx64:
    """Craft SROP payload for x86-64

    Fields
    ------
    ``SROPx64`` exposes a number of integer fields corresponding to the Linux
    signal frame / ucontext layout, plus a computed payload.

    - The computed payload is available as ``payload``.
    - Register / context values are writable attributes (e.g. ``rip``, ``rdi``, ``rsp``).

    (The full field list is intentionally omitted here to keep the docstring
    compatible with multiple doc generators.)

    Examples:
        .. code-block:: python

            srop = SROPx64(rip=0x401c20, rdi=0x404058)
            print(srop.payload)

            srop.rsp = 0x404400
            srop.rip = 0x401c40
            print(srop.payload)
    """
    def __init__(self, **kwargs: int):
        self.uc_flags = kwargs.get('uc_flags', 0)
        self.uc_link  = kwargs.get('uc_link', 0)
        self.ss_sp    = kwargs.get('ss_sp', 0)
        self.ss_flags = kwargs.get('ss_flags', 0)
        self.ss_size  = kwargs.get('ss_size', 0)
        self.r8  = kwargs.get('r8', 0)
        self.r9  = kwargs.get('r9', 0)
        self.r10 = kwargs.get('r10', 0)
        self.r11 = kwargs.get('r11', 0)
        self.r12 = kwargs.get('r12', 0)
        self.r13 = kwargs.get('r13', 0)
        self.r14 = kwargs.get('r14', 0)
        self.r15 = kwargs.get('r15', 0)
        self.rdi = kwargs.get('rdi', 0)
        self.rsi = kwargs.get('rsi', 0)
        self.rbp = kwargs.get('rbp', 0)
        self.rbx = kwargs.get('rbx', 0)
        self.rdx = kwargs.get('rdx', 0)
        self.rax = kwargs.get('rax', 0)
        self.rcx = kwargs.get('rcx', 0)
        self.rsp = kwargs.get('rsp', 0)
        self.rip = kwargs.get('rip', 0)
        self.eflags = kwargs.get('eflags', 0)
        self.cs   = kwargs.get('cs', 0x33)
        self.gs   = kwargs.get('gs', 0)
        self.fs   = kwargs.get('fs', 0)
        self.pad0 = kwargs.get('pad0', 0)
        self.err  = kwargs.get('err', 0)
        self.trapno   = kwargs.get('trapno', 0)
        self.oldmask  = kwargs.get('oldmask', 0)
        self.cr2      = kwargs.get('cr2', 0)
        self.pfpstate = kwargs.get('pfpstate', 0)
        self.reserved = kwargs.get('reserved', 0)
        self.mask     = kwargs.get('mask', 0)
        self.fpstate  = kwargs.get('fpstate', 0)

    @property
    def payload(self) -> bytes:
        """Get payload bytes for SROP.
        """
        return flat([
            self.uc_flags, self.uc_link, self.ss_sp, self.ss_flags,
            self.ss_size, self.r8, self.r9, self.r10,
            self.r11, self.r12, self.r13, self.r14,
            self.r15, self.rdi, self.rsi, self.rbp,
            self.rbx, self.rdx, self.rax, self.rcx,
            self.rsp, self.rip, self.eflags,
            self.cs | (self.gs << 16) | (self.fs << 32) | (self.pad0 << 48),
            self.err, self.trapno, self.oldmask, self.cr2,
            self.pfpstate, self.reserved, self.mask, self.fpstate
        ], map=p64)


__all__ = ['SROP', 'SROPx64']
