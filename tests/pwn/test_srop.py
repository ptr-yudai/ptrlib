"""This package provides some tests for SROP feature.
"""
import random
import unittest
from logging import FATAL, getLogger

from ptrlib import SROPx64, u16, u64


class TestSROP(unittest.TestCase):
    """Tests for SROP class.
    """
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_srop_x64(self):
        """Test SROPx64 class.
        """
        (uc_flags, uc_link, ss_sp, ss_flags, ss_size,
         r8, r9, r10, r11, r12, r13, r14, r15,
         rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip,
         eflags, err, trapno, oldmask, cr2, pfpstate,
         mask, fpstate) = (random.randrange(0, 1<<64) for _ in range(30))
        gs = random.randrange(0, 1<<16)
        fs = random.randrange(0, 1<<16)

        srop = SROPx64(
            uc_flags=uc_flags, uc_link=uc_link,
            ss_sp=ss_sp, ss_flags=ss_flags, ss_size=ss_size,
            r8=r8, r9=r9, r10=r10, r11=r11, r12=r12, r13=r13, r14=r14, r15=r15,
            rdi=rdi, rsi=rsi, rbp=rbp, rbx=rbx, rdx=rdx, rax=rax,
            rcx=rcx, rsp=rsp, rip=rip, eflags=eflags, err=err,
            trapno=trapno, oldmask=oldmask, cr2=cr2, pfpstate=pfpstate,
            mask=mask, fpstate=fpstate, gs=gs, fs=fs
        )

        self.assertEqual(u64(srop.payload[0x00:0x08]), uc_flags)
        self.assertEqual(u64(srop.payload[0x08:0x10]), uc_link)
        self.assertEqual(u64(srop.payload[0x10:0x18]), ss_sp)
        self.assertEqual(u64(srop.payload[0x18:0x20]), ss_flags)
        self.assertEqual(u64(srop.payload[0x20:0x28]), ss_size)
        self.assertEqual(u64(srop.payload[0x28:0x30]), r8)
        self.assertEqual(u64(srop.payload[0x30:0x38]), r9)
        self.assertEqual(u64(srop.payload[0x38:0x40]), r10)
        self.assertEqual(u64(srop.payload[0x40:0x48]), r11)
        self.assertEqual(u64(srop.payload[0x48:0x50]), r12)
        self.assertEqual(u64(srop.payload[0x50:0x58]), r13)
        self.assertEqual(u64(srop.payload[0x58:0x60]), r14)
        self.assertEqual(u64(srop.payload[0x60:0x68]), r15)
        self.assertEqual(u64(srop.payload[0x68:0x70]), rdi)
        self.assertEqual(u64(srop.payload[0x70:0x78]), rsi)
        self.assertEqual(u64(srop.payload[0x78:0x80]), rbp)
        self.assertEqual(u64(srop.payload[0x80:0x88]), rbx)
        self.assertEqual(u64(srop.payload[0x88:0x90]), rdx)
        self.assertEqual(u64(srop.payload[0x90:0x98]), rax)
        self.assertEqual(u64(srop.payload[0x98:0xa0]), rcx)
        self.assertEqual(u64(srop.payload[0xa0:0xa8]), rsp)
        self.assertEqual(u64(srop.payload[0xa8:0xb0]), rip)
        self.assertEqual(u64(srop.payload[0xb0:0xb8]), eflags)
        self.assertEqual(u16(srop.payload[0xb8:0xba]), 0x33)
        self.assertEqual(u16(srop.payload[0xba:0xbc]), gs)
        self.assertEqual(u16(srop.payload[0xbc:0xbe]), fs)
        self.assertEqual(u16(srop.payload[0xbe:0xc0]), 0)
        self.assertEqual(u64(srop.payload[0xc0:0xc8]), err)
        self.assertEqual(u64(srop.payload[0xc8:0xd0]), trapno)
        self.assertEqual(u64(srop.payload[0xd0:0xd8]), oldmask)
        self.assertEqual(u64(srop.payload[0xd8:0xe0]), cr2)
        self.assertEqual(u64(srop.payload[0xe0:0xe8]), pfpstate)
        self.assertEqual(u64(srop.payload[0xe8:0xf0]), 0)
        self.assertEqual(u64(srop.payload[0xf0:0xf8]), mask)
        self.assertEqual(u64(srop.payload[0xf8:0x100]), fpstate)
