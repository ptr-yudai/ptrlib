from ptrlib.binary.packing.pack import p64
from ptrlib.binary.packing.flat import flat

__all__ = ['sigreturn_frame_x64']

def sigreturn_frame_x64(uc_flags: int = 0, uc_link: int = 0,
                        ss_sp: int = 0, ss_flags: int = 0, ss_size: int = 0,
                        r8: int = 0, r9: int = 0, r10: int = 0,
                        r11: int = 0, r12: int = 0, r13: int = 0,
                        r14: int = 0, r15: int = 0, rdi: int = 0,
                        rsi: int = 0, rbp: int = 0, rbx: int = 0,
                        rdx: int = 0, rax: int = 0, rcx: int = 0,
                        rsp: int = 0, rip: int = 0, eflags: int = 0,
                        cs: int = 0x33, gs: int = 0, fs: int = 0, pad0: int = 0,
                        err: int = 0, trapno: int = 0, oldmask: int = 0,
                        cr2: int = 0, pfpstate: int = 0, reserved: int = 0,
                        mask: int = 0, fpstate: int = 0) -> bytes:
    """Create sigreturn frame for x64
    """
    return flat([
        uc_flags, uc_link, ss_sp, ss_flags, ss_size,
        r8, r9, r10, r11, r12, r13, r14, r15,
        rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip,
        eflags, cs | (gs << 16) | (fs << 32) | (pad0 << 48),
        err, trapno, oldmask, cr2, pfpstate, reserved, mask, fpstate
    ], map=p64)