import enum
from typing import Generator, List, Optional

# Based on https://bjh21.me.uk/all-escapes/all-escapes.txt

class AnsiOp(enum.Enum):
    UNKNOWN = 0

    # C0 Control Sequence
    BEL = 0x10
    BS = enum.auto()
    HT = enum.auto()
    LF = enum.auto()
    FF = enum.auto()
    CR = enum.auto()
    ESC = enum.auto()

    # Fe Escape Sequence
    BPH = 0x20        # Break permitted here
    NBH = enum.auto() # No break here
    IND = enum.auto() # Index
    NEL = enum.auto() # Next line
    SSA = enum.auto() # Start of selected area
    ESA = enum.auto() # End of selected area
    HTS = enum.auto() # Character tabulation set
    HTJ = enum.auto() # Character tabulation with justification
    VTS = enum.auto() # Line tabulation set
    PLD = enum.auto() # Partial line forward
    PLU = enum.auto() # Partial line backward
    RI  = enum.auto() # Reverse line feed
    SS2 = enum.auto() # Single-shift two
    SS3 = enum.auto() # Single-shift three
    DCS = enum.auto() # Device control string
    PU1 = enum.auto() # Private use one
    PU2 = enum.auto() # Private use two
    STS = enum.auto() # Set transmit state
    CCH = enum.auto() # Cancel character
    MW  = enum.auto() # Message waiting
    SPA = enum.auto() # Start of guarded area
    EPA = enum.auto() # End of guarded area
    SOS = enum.auto() # Start of string
    SCI = enum.auto() # Single character introducer
    CSI = enum.auto() # Control sequence

    # CSI Sequence
    ICH = 0x100       # Insert character
    SBC = enum.auto() # Set border color
    CUU = enum.auto() # Cursor up
    SBP = enum.auto() # Set bell parameters
    CUD = enum.auto() # Cursor down
    SCR = enum.auto() # Set cursor parameters
    CUF = enum.auto() # Cursor right
    SBI = enum.auto() # Set background intensity
    CUB = enum.auto() # Cursor left
    SBB = enum.auto() # Set background blink bit
    CNL = enum.auto() # Cursor next line
    SNF = enum.auto() # Set normal foreground color
    CPL = enum.auto() # Cursor preceding line
    SNB = enum.auto() # Set normal background color
    CHA = enum.auto() # Cursor character absolute
    SRF = enum.auto() # Set reverse foreground color
    CUP = enum.auto() # Cursor position
    SRB = enum.auto() # Set reverse background color
    CHT = enum.auto() # Cursor forward tabulation
    ED  = enum.auto() # Erase in page
    SGF = enum.auto() # Set graphic foreground color
    EL  = enum.auto() # Erase in line
    SGB = enum.auto() # Set graphic background color
    IL  = enum.auto() # Insert line
    SEF = enum.auto() # Set emulator feature
    DL  = enum.auto() # Delete line
    RAS = enum.auto() # Return attribute setting
    EF  = enum.auto() # Erase in field
    EA  = enum.auto() # Erase in area
    DCH = enum.auto() # Delete character
    SEE = enum.auto() # Select editing extent
    CPR = enum.auto() # Active position report
    SU  = enum.auto() # Scroll up
    SD  = enum.auto() # Scroll down
    NP  = enum.auto() # Next page
    PP  = enum.auto() # Preceding page
    CTC = enum.auto() # Cursor tabulation control
    ECH = enum.auto() # Erase character
    CVT = enum.auto() # Cursor line tabulation
    CBT = enum.auto() # Cursor backward tabulation
    SRS = enum.auto() # Start reversed string
    PTX = enum.auto() # Parallel texts
    SDS = enum.auto() # Start directed string
    SIMD = enum.auto() # Select implicit movement direction
    

class AnsiInstruction(object):
    def __init__(self,
                 c0: AnsiOp,
                 code: Optional[AnsiOp]=None,
                 args: Optional[List[int]]=None):
        self._c0   = c0
        self._code = code
        self._args = args

    @property
    def args(self):
        return self._args

    def __str__(self):
        return f'<c0={self._c0}, code={self._code}, args={self._args}>'

class AnsiParser(object):
    CTRL = [0x1b, 0x07, 0x08, 0x09, 0x0a, 0x0c, 0x0d]
    ESC, BEL, BS, HT, LF, FF, CR = CTRL

    def __init__(self,
                 generator: Generator[bytes, None, None]):
        """
        Args:
            generator: A generator which yields byte stream
        """
        self._g = generator
        self._buffer = b''

    def _decode_csi(self) -> Optional[AnsiInstruction]:
        """Decode a CSI sequence
        """
        c0, code = AnsiOp.ESC, AnsiOp.CSI

        # Parse parameters
        mode_set = 0
        cur = 2
        args = []

        if cur < len(self._buffer) and self._buffer[cur] == ord('='):
            mode_set = 1
            cur += 1

        while True:
            prev = cur
            while cur < len(self._buffer) and 0x30 <= self._buffer[cur] <= 0x39:
                cur += 1

            if cur >= len(self._buffer):
                return None

            # NOTE: Common implementation seems to skip successive delimiters
            if cur != prev:
                args.append(int(self._buffer[prev:cur]))

            if self._buffer[cur] == ord(';'):
                cur += 1
            else:
                break

        # Check mnemonic
        if self._buffer[cur] == ord('@'):
            code = AnsiOp.ICH
            default = (1,)
        elif self._buffer[cur] == ord('A'):
            code = [AnsiOp.CUU, AnsiOp.SBC][mode_set]
            default = [(1,), ()][mode_set]
        elif self._buffer[cur] == ord('B'):
            code = [AnsiOp.CUD, AnsiOp.SBP][mode_set]
            default = [(1,), ()][mode_set]
        elif self._buffer[cur] == ord('C'):
            code = [AnsiOp.CUF, AnsiOp.SCR][mode_set]
            default = [(1,), ()][mode_set]
        elif self._buffer[cur] == ord('D'):
            code = [AnsiOp.CUB, AnsiOp.SBI][mode_set]
            default = [(1,), ()][mode_set]
        elif self._buffer[cur] == ord('E'):
            code = [AnsiOp.CNL, AnsiOp.SBB][mode_set]
            default = [(1,), ()][mode_set]
        elif self._buffer[cur] == ord('F'):
            code = [AnsiOp.CPL, AnsiOp.SNF][mode_set]
            default = [(1,), ()][mode_set]
        elif self._buffer[cur] == ord('G'):
            code = [AnsiOp.CHA, AnsiOp.SNB][mode_set]
            default = [(1,), ()][mode_set]
        elif self._buffer[cur] == ord('H'):
            code = [AnsiOp.CUP, AnsiOp.SRF][mode_set]
            default = [(1,1), ()][mode_set]
        elif self._buffer[cur] == ord('I'):
            # TODO: Support screen saver off
            code = [AnsiOp.CHT, AnsiOp.SRB][mode_set]
            default = [(1,), ()][mode_set]
        elif self._buffer[cur] == ord('J'):
            # TODO: Support DECSED and screen saver on
            code = [AnsiOp.ED, AnsiOp.SGF][mode_set]
            default = [(0,), ()][mode_set]
        elif self._buffer[cur] == ord('K'):
            # TODO: Support DECSEL
            code = [AnsiOp.EL, AnsiOp.SGB][mode_set]
            default = [(0,), ()][mode_set]
        elif self._buffer[cur] == ord('L'):
            code = [AnsiOp.IL, AnsiOp.SEF][mode_set]
            default = [(1,), ()][mode_set]
        elif self._buffer[cur] == ord('M'):
            code = [AnsiOp.DL, AnsiOp.RAS][mode_set]
            default = [(1,), ()][mode_set]
        elif self._buffer[cur] == ord('N'):
            code, default = AnsiOp.EF, (0,)
            default = (0,)
        elif self._buffer[cur] == ord('O'):
            code, default = AnsiOp.EA, (0,)
        elif self._buffer[cur] == ord('P'):
            code, default = AnsiOp.DCH, (1,)
        elif self._buffer[cur] == ord('Q'):
            code, default = AnsiOp.SEE, (0,)
        elif self._buffer[cur] == ord('R'):
            # TODO: Support DECXCPR
            code, default = AnsiOp.CPR, (1, 1)
        elif self._buffer[cur] == ord('S'):
            code, default = AnsiOp.SU, (1,)
        elif self._buffer[cur] == ord('T'):
            # TODO: Support initiate hilite mouse tracking
            code, default = AnsiOp.SD, (1,)
        elif self._buffer[cur] == ord('U'):
            code, default = AnsiOp.NP, (1,)
        elif self._buffer[cur] == ord('V'):
            code, default = AnsiOp.PP, (1,)
        elif self._buffer[cur] == ord('W'):
            # TODO: Support DECST8C
            code, default = AnsiOp.CTC, (0,)
        elif self._buffer[cur] == ord('X'):
            code, default = AnsiOp.ECH, (1,)
        elif self._buffer[cur] == ord('Y'):
            code, default = AnsiOp.CVT, (1,)
        elif self._buffer[cur] == ord('Z'):
            code, default = AnsiOp.CBT, (1,)
        elif self._buffer[cur] == ord('['):
            # TODO: Support ignore next character
            code, default = AnsiOp.SRS, (0,)
        elif self._buffer[cur] == ord('\\'):
            code, default = AnsiOp.PTX, (0,)
        elif self._buffer[cur] == ord(']'):
            # TODO: Support linux private sequences
            code, default = AnsiOp.SDS, (0,)
        elif self._buffer[cur] == ord('^'):
            code, default = AnsiOp.SIMD, (0,)
            

        self._buffer = self._buffer[cur+1:]
        return AnsiInstruction(c0, code, args)

    def _decode_esc(self) -> Optional[AnsiInstruction]:
        """Decode an ESC sequence
        """
        if len(self._buffer) < 2:
            return None

        c0   = AnsiOp.ESC
        code = AnsiOp.UNKNOWN
        if self._buffer[1] == ord('B'):
            code = AnsiOp.BPH
        elif self._buffer[1] == ord('C'):
            code = AnsiOp.NBH
        elif self._buffer[1] == ord('D'):
            code = AnsiOp.IND
        elif self._buffer[1] == ord('E'):
            code = AnsiOp.NEL
        elif self._buffer[1] == ord('F'):
            code = AnsiOp.SSA
        elif self._buffer[1] == ord('G'):
            code = AnsiOp.ESA
        elif self._buffer[1] == ord('H'):
            code = AnsiOp.HTS
        elif self._buffer[1] == ord('I'):
            code = AnsiOp.HTJ
        elif self._buffer[1] == ord('J'):
            code = AnsiOp.VTS
        elif self._buffer[1] == ord('K'):
            code = AnsiOp.PLD
        elif self._buffer[1] == ord('L'):
            code = AnsiOp.PLU
        elif self._buffer[1] == ord('M'):
            code = AnsiOp.RI
        elif self._buffer[1] == ord('N'):
            code = AnsiOp.SS2
        elif self._buffer[1] == ord('O'):
            code = AnsiOp.SS3
        elif self._buffer[1] == ord('P'):
            code = AnsiOp.DCS
        elif self._buffer[1] == ord('Q'):
            code = AnsiOp.PU1
        elif self._buffer[1] == ord('R'):
            code = AnsiOp.PU2
        elif self._buffer[1] == ord('S'):
            code = AnsiOp.STS
        elif self._buffer[1] == ord('T'):
            code = AnsiOp.CCH
        elif self._buffer[1] == ord('U'):
            code = AnsiOp.MW
        elif self._buffer[1] == ord('V'):
            code = AnsiOp.SPA
        elif self._buffer[1] == ord('W'):
            code = AnsiOp.EPA
        elif self._buffer[1] == ord('X'):
            code = AnsiOp.SOS
        elif self._buffer[1] == ord('Z'):
            code = AnsiOp.SCI
        elif self._buffer[1] == ord('['):
            return self._decode_csi()

        return AnsiInstruction(c0, code)

        """
        elif self._buffer[1] == 0x5c:
            code = AnsiOp.ST
        elif self._buffer[1] == 0x5d:
            code = AnsiOp.OSC
        elif self._buffer[1] == 0x5e:
            code = AnsiOp.PM
        elif self._buffer[1] == 0x5f:
            code = AnsiOp.APC
        """

    def parse_block(self) -> Optional[AnsiInstruction]:
        """Parse a block of ANSI escape sequence

        Returns:
            AnsiInstruction: Instruction, or None if need more data

        Raises:
            StopIteration: No more data to receive
        """
        try:
            self._buffer += next(self._g)
        except StopIteration:
            pass
        while len(self._buffer) == 0:
            self._buffer += next(self._g)

        # TODO: Support C1 control code
        if self._buffer[0] not in AnsiParser.CTRL:
            # Return until a control code appears
            for i, c in enumerate(self._buffer):
                if c in AnsiParser.CTRL:
                    data, self._buffer = self._buffer[:i], self._buffer[i:]
                    return data

            data, self._buffer = self._buffer, b''
            return data

        # Check C0 control sequence
        if self._buffer[0] == AnsiParser.BEL: # BEL
            instr = AnsiInstruction(AnsiOp.BEL)
        elif self._buffer[0] == AnsiParser.BS: # BS
            instr = AnsiInstruction(AnsiOp.BS)
        elif self._buffer[0] == AnsiParser.HT: # HT
            instr = AnsiInstruction(AnsiOp.HT)
        elif self._buffer[0] == AnsiParser.LF: # LF
            instr = AnsiInstruction(AnsiOp.LF)
        elif self._buffer[0] == AnsiParser.FF: # FF
            instr = AnsiInstruction(AnsiOp.FF)
        elif self._buffer[0] == AnsiParser.CR: # CR
            instr = AnsiInstruction(AnsiOp.CR)
        else:
            return self._decode_esc()

        self._buffer = self._buffer[1:]
        return instr

if __name__ == '__main__':
    def test():
        yield b"ABC\n\x1b[12;23H\x08\x1b[30"
        yield b"m\x1b[47mHello"

    ansi = AnsiParser(test())
    print(ansi.parse_block())
    print(ansi.parse_block())
    print(ansi.parse_block())
    print(ansi.parse_block())
    print(ansi.parse_block())
    print(ansi.parse_block())
    print(ansi.parse_block())
    print(ansi.parse_block())
    
