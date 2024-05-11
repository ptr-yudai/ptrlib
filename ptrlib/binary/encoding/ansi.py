import enum
from logging import getLogger
from typing import Callable, Generator, List, Optional, Tuple, Union

logger = getLogger(__name__)


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

    # Fp Private Control Functions
    DECKPAM = 0x80

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
    HPA = enum.auto() # Character position absolute
    HPR = enum.auto() # Character position forward
    REP = enum.auto() # Repeat
    DA  = enum.auto() # Device attributes
    HSC = enum.auto() # Hide or show cursor
    VPA = enum.auto() # Line position absolute
    VPR = enum.auto() # Line position forward
    HVP = enum.auto() # Character and line position
    TBC = enum.auto() # Tabulation clear
    PRC = enum.auto() # Print ROM character
    SM  = enum.auto() # Set mode
    MC  = enum.auto() # Media copy
    HPB = enum.auto() # Character position backward
    VPB = enum.auto() # Line position backward
    RM  = enum.auto() # Reset mode
    CHC = enum.auto() # Clear and home cursor
    SGR = enum.auto() # Select graphic rendition
    SSM = enum.auto() # Set specific margin
    DSR = enum.auto() # Device status report
    DAQ = enum.auto() # Device area qualification
    DECSSL = enum.auto() # Select set-up language
    DECLL  = enum.auto() # Load LEDs
    DECSTBM = enum.auto() # Set top and bottom margins
    RSM = enum.auto() # Reset margins
    SCP = enum.auto() # Save cursor position
    DECSLPP = enum.auto() # Set lines per physical page
    RCP = enum.auto() # Reset cursor position
    DECSVTS = enum.auto() # Set vertical tab stops
    DECSHORP = enum.auto() # Set horizontal pitch
    DGRTC = enum.auto() # Request terminal configuration
    DECTST = enum.auto() # Invoke confidence test
    SSW = enum.auto() # Screen switch
    CAT = enum.auto() # Clear all tabs

    # SCS: Select character set
    SCS_B = 0x200 # Default charset
    SCS_0 = enum.auto() # DEC special charset

class AnsiInstruction(object):
    def __init__(self,
                 c0: AnsiOp,
                 code: Optional[AnsiOp]=None,
                 args: Optional[List[int]]=None):
        self._c0   = c0
        self._code = code
        self._args = args

    @property
    def is_skip(self):
        """Check if instruction can be skipped

        Returns:
            bool: True if this instruction is not important for drawing screen
        """
        return self._code in [
            AnsiOp.DECKPAM,
            AnsiOp.DECSLPP,
            AnsiOp.DECSTBM,
            AnsiOp.SGR,
        ]

    def __getitem__(self, i: int):
        assert isinstance(i, int), "Slice must be integer"
        if i < 0 or i >= len(self._args):
            return None
        else:
            return self._args[i]

    def __eq__(self, other):
        if isinstance(other, AnsiInstruction):
            return self._c0 == other._c0 and \
                self._code == other._code and \
                self._args == other._args

        elif isinstance(other, AnsiOp):
            return self._c0 == other or self._code == other

        else:
            raise TypeError(f"Cannot compare AnsiInstruction and {type(other)}")

    def __neq__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return f'<c0={self._c0}, code={self._code}, args={self._args}>'

class AnsiParser(object):
    CTRL = [0x1b, 0x07, 0x08, 0x09, 0x0a, 0x0c, 0x0d]
    ESC, BEL, BS, HT, LF, FF, CR = CTRL

    def __init__(self,
                 generator: Generator[bytes, None, None],
                 size: Tuple[int, int]=(0, 0),
                 pos: Tuple[int, int]=(0, 0)):
        """
        Args:
            generator: A generator which yields byte stream
            size: Initial screen size (width, height)
            pos: Initial cursor position (x, y)
        """
        self._g = generator
        self._buffer = b''
        self._width, self._height = size
        self._x, self._y = pos
        self._last_size = 0

    @property
    def buffer(self) -> bytes:
        """Return contents of current buffering
        """
        return self._buffer

    def _experimantal_warning(self, message: str):
        logger.error(message)
        logger.error("This feature is experimental and does not support some ANSI codes.\n" \
                     "If you encounter this error, please create an issue here:\n" \
                     "https://github.com/ptr-yudai/ptrlib/issues")

    def _decode_csi(self) -> Optional[AnsiInstruction]:
        """Decode a CSI sequence
        """
        c0, code = AnsiOp.ESC, AnsiOp.CSI

        # Parse parameters
        mode_set, mode_q, mode_private = 0, 0, 0
        cur = 2
        args = []

        while cur < len(self._buffer) and self._buffer[cur] in [ord('='), ord('?'), ord('>')]:
            if self._buffer[cur] == ord('='):
                mode_set = 1
            elif self._buffer[cur] == ord('?'):
                mode_q = 1
            elif self._buffer[cur] == ord('>'): # TODO: Is this correct?
                mode_private = 1
            else:
                raise NotImplementedError("BUG: Unreachable path")
            cur += 1

        while True:
            prev = cur
            while cur < len(self._buffer) and 0x30 <= self._buffer[cur] <= 0x39:
                cur += 1

            if cur >= len(self._buffer):
                self._last_size = len(self._buffer)
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
        elif self._buffer[cur] == ord('`'):
            code, default = AnsiOp.HPA, (1,)
        elif self._buffer[cur] == ord('a'):
            code, default = AnsiOp.HPR, (1,)
        elif self._buffer[cur] == ord('b'):
            code, default = AnsiOp.REP, (1,)
        elif self._buffer[cur] == ord('c'):
            # NOTE: This operation has a lot of meanings
            code = [AnsiOp.DA, AnsiOp.HSC][mode_set]
            default = [(0,), ()][mode_set]
        elif self._buffer[cur] == ord('d'):
            code, default = AnsiOp.VPA, (1,)
        elif self._buffer[cur] == ord('e'):
            code, default = AnsiOp.VPR, (1,)
        elif self._buffer[cur] == ord('f'):
            code, default = AnsiOp.HVP, (1, 1)
        elif self._buffer[cur] == ord('g'):
            # TODO: Support reset tabs
            code = [AnsiOp.TBC, AnsiOp.PRC][mode_set]
            default = [(0,), ()][mode_set]
        elif self._buffer[cur] == ord('h'):
            code, default = AnsiOp.SM, ()
        elif self._buffer[cur] == ord('i'):
            code, default = AnsiOp.MC, ()
        elif self._buffer[cur] == ord('j'):
            code, default = AnsiOp.HPB, (1,)
        elif self._buffer[cur] == ord('k'):
            code, default = AnsiOp.VPB, (1,)
        elif self._buffer[cur] == ord('l'):
            # TODO: Support insert line up
            code = [AnsiOp.RM, AnsiOp.CHC][mode_set]
            default = [(1,), ()][mode_set]
        elif self._buffer[cur] == ord('m'):
            # TODO: Support delete line down
            code = [AnsiOp.SGR, AnsiOp.SSM][mode_set]
            default = [(0,), ()][mode_set]
        elif self._buffer[cur] == ord('n'):
            code, default = AnsiOp.DSR, (0,)
        elif self._buffer[cur] == ord('o'):
            code, default = AnsiOp.DAQ, (0,)
        elif self._buffer[cur] == ord('p'):
            code, default = AnsiOp.DECSSL, ()
        elif self._buffer[cur] == ord('q'):
            code, default = AnsiOp.DECLL, ()
        elif self._buffer[cur] == ord('r'):
            # TODO: Support CSR and SUNSCRL
            code = [AnsiOp.DECSTBM, AnsiOp.RSM][mode_set]
            default = [(), ()][mode_set]
        elif self._buffer[cur] == ord('s'):
            code, default = AnsiOp.SCP, ()
        elif self._buffer[cur] == ord('t'):
            code, default = AnsiOp.DECSLPP, ()
        elif self._buffer[cur] == ord('u'):
            code, default = AnsiOp.RCP, ()
        elif self._buffer[cur] == ord('v'):
            code, default = AnsiOp.DECSVTS, ()
        elif self._buffer[cur] == ord('w'):
            code, default = AnsiOp.DECSHORP, ()
        elif self._buffer[cur] == ord('x'):
            code, default = AnsiOp.DGRTC, ()
        elif self._buffer[cur] == ord('y'):
            code, default = AnsiOp.DECTST, ()
        elif self._buffer[cur] == ord('z'):
            # TODO: Support 
            code = [AnsiOp.SSW, AnsiOp.CAT][mode_set]
            default = [(), ()][mode_set]
        else:
            self._experimantal_warning(f"CSI not implemented: {self._buffer[cur-2:cur+0x10]}")
            raise NotImplementedError("Unknown CSI")

        if len(args) < len(default):
            args = tuple(args + list(default[len(args):]))

        self._buffer = self._buffer[cur+1:]
        return AnsiInstruction(c0, code, args)

    def _decode_esc(self) -> Optional[AnsiInstruction]:
        """Decode an ESC sequence
        """
        c0   = AnsiOp.ESC
        code = AnsiOp.UNKNOWN

        cur = 1
        if len(self._buffer) <= cur:
            self._last_size = len(self._buffer)
            return None

        if self._buffer[cur] == ord('['):
            cur += 1
            if self._buffer[cur] == ord('B'):
                code = AnsiOp.BPH
            elif self._buffer[cur] == ord('C'):
                code = AnsiOp.NBH
            elif self._buffer[cur] == ord('D'):
                code = AnsiOp.IND
            elif self._buffer[cur] == ord('E'):
                code = AnsiOp.NEL
            elif self._buffer[cur] == ord('F'):
                code = AnsiOp.SSA
            elif self._buffer[cur] == ord('G'):
                code = AnsiOp.ESA
            elif self._buffer[cur] == ord('H'):
                code = AnsiOp.HTS
            elif self._buffer[cur] == ord('I'):
                code = AnsiOp.HTJ
            elif self._buffer[cur] == ord('J'):
                code = AnsiOp.VTS
            elif self._buffer[cur] == ord('K'):
                code = AnsiOp.PLD
            elif self._buffer[cur] == ord('L'):
                code = AnsiOp.PLU
            elif self._buffer[cur] == ord('M'):
                code = AnsiOp.RI
            elif self._buffer[cur] == ord('N'):
                code = AnsiOp.SS2
            elif self._buffer[cur] == ord('O'):
                code = AnsiOp.SS3
            elif self._buffer[cur] == ord('P'):
                code = AnsiOp.DCS
            elif self._buffer[cur] == ord('Q'):
                code = AnsiOp.PU1
            elif self._buffer[cur] == ord('R'):
                code = AnsiOp.PU2
            elif self._buffer[cur] == ord('S'):
                code = AnsiOp.STS
            elif self._buffer[cur] == ord('T'):
                code = AnsiOp.CCH
            elif self._buffer[cur] == ord('U'):
                code = AnsiOp.MW
            elif self._buffer[cur] == ord('V'):
                code = AnsiOp.SPA
            elif self._buffer[cur] == ord('W'):
                code = AnsiOp.EPA
            elif self._buffer[cur] == ord('X'):
                code = AnsiOp.SOS
            elif self._buffer[cur] == ord('Z'):
                code = AnsiOp.SCI
            else:
                return self._decode_csi()

        elif self._buffer[cur] == ord('('):
            cur += 1
            if len(self._buffer) <= cur:
                self._last_size = len(self._buffer)
                return None

            if self._buffer[cur] == ord('B'):
                code = AnsiOp.SCS_B
            elif self._buffer[cur] == ord('0'):
                code = AnsiOp.SCS_0
            else:
                self._experimantal_warning(f"ESC not implemented: {self._buffer[cur-2:cur+0x10]}")
                raise NotImplementedError(f"Unknown ESC")

        elif self._buffer[cur] == ord('='):
            code = AnsiOp.DECKPAM

        else:
            self._experimantal_warning(f"ESC not implemented: {self._buffer[cur-2:cur+0x10]}")
            raise NotImplementedError(f"Unknown ESC")

        self._buffer = self._buffer[cur+1:]
        return AnsiInstruction(c0, code)

    def parse_block(self) -> Optional[Union[bytes, AnsiInstruction]]:
        """Parse a block of ANSI escape sequence

        Returns:
            AnsiInstruction: Instruction, or None if need more data

        Raises:
            StopIteration: No more data to receive
        """
        if len(self._buffer) <= self._last_size:
            try:
                self._buffer += next(self._g)
            except StopIteration as e:
                if len(self._buffer) == 0:
                    # All processed, end of input
                    raise e from None

        self._last_size = 0

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

    def _update_screen_size(self, screen):
        if len(screen) == 0:
            return
        self._width  = max(map(lambda pos: pos[0], screen.keys())) + 1
        self._height = max(map(lambda pos: pos[1], screen.keys())) + 1

    def _special_char(self, charset: AnsiOp, c: int):
        if charset == AnsiOp.SCS_B:
            return c

        elif charset == AnsiOp.SCS_0:
            if 0x5f <= c <= 0x7e:
                return [0x20, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x6f,
                        0x2b, 0x3f, 0x3f, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b,
                        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2b, 0x2b, 0x2b,
                        0x2b, 0x7c, 0x3c, 0x3e, 0x6e, 0x3d, 0x66, 0x2e][c - 0x5f]
            else:
                return c

        else:
            self._experimantal_warning(f"Character set not implemented: {charset}")
            raise NotImplementedError("Unknown character set")

    def draw_screen(self,
                    returns: type=list,
                    stop: Optional[Callable[[AnsiInstruction], bool]]=None) -> list:
        """Receive a screen

        Args:
            returns: Either str or list
            stop: Function to determine when to stop emulating instructions
        """
        if stop is None:
            # Default stop checker designed for ncurses games
            stop = lambda instr: instr == AnsiOp.HTS

        # NOTE: These variables are global so that we can support
        #       successive draws in the future
        self._width = self._height = 0

        screen = {}
        charset = AnsiOp.SCS_B
        DEL = 0x20 # Empty
        last_char = DEL
        stop_recv = False
        while not stop_recv:
            instr = None
            try:
                while instr is None:
                    instr = self.parse_block()
            except StopIteration:
                break

            stop_recv = stop(instr)

            if isinstance(instr, bytes):
                # TODO: Reverse order?
                for c in instr:
                    screen[(self._x, self._y)] = self._special_char(charset, c)
                    self._x += 1
                    last_char = c

            else:
                if instr.is_skip:
                    continue

                elif instr == AnsiOp.SCS_B: # English mode
                    charset = AnsiOp.SCS_B

                elif instr == AnsiOp.BS: # Back space
                    self._x = max(0, self._x - 1)
                    stop_recv = True

                elif instr == AnsiOp.CHA: # Cursor character absolute
                    self._x = instr[0] - 1

                elif instr == AnsiOp.SCS_0: # DEC special graphic
                    charset = AnsiOp.SCS_0

                elif instr == AnsiOp.CR: # Carriage return
                    self._x, self._y = 0, self._y + 1

                elif instr == AnsiOp.CUP: # Cursor position
                    self._x, self._y = instr[1] - 1, instr[0] - 1

                elif instr == AnsiOp.ECH: # Erase character
                    for x in range(self._x, self._x + instr[0]):
                        screen[(x, self._y)] = DEL

                elif instr == AnsiOp.ED: # Erase in page
                    self._update_screen_size(screen)
                    if instr[0] == 0:
                        for y in range(self._y, self._height):
                            screen[(self._x, y)] = DEL
                    elif instr[0] == 1:
                        for y in range(self._y + 1):
                            screen[(self._x, y)] = DEL
                    elif instr[0] == 2:
                        for y in range(self._height):
                            screen[(self._x, y)] = DEL

                elif instr == AnsiOp.EL: # Erase in line
                    self._update_screen_size(screen)
                    if instr[0] == 0:
                        for x in range(self._x, self._width):
                            screen[(x, self._y)] = DEL
                    elif instr[0] == 1:
                        for x in range(self._x + 1):
                            screen[(x, self._y)] = DEL
                    elif instr[0] == 2:
                        for x in range(self._width):
                            screen[(x, self._y)] = DEL

                elif instr == AnsiOp.HTS:
                    self._x, self._y = 0, 0

                elif instr == AnsiOp.LF:
                    self._x, self._y = 0, self._y + 1

                elif instr == AnsiOp.REP: # Repeat
                    for x in range(self._x, self._x + instr[0]):
                        screen[(x, self._y)] = self._special_char(charset, last_char)
                    self._x += instr[0]

                elif instr == AnsiOp.RM: # Reset mode
                    pass # TODO: ?

                elif instr == AnsiOp.SM: # Set mode
                    pass # TODO: ?

                elif instr == AnsiOp.VPA: # Line position absolute
                    self._y = instr[0] - 1

                else:
                    raise ValueError(f"Emulation not supported for instruction {instr}")

        self._update_screen_size(screen)
        field = [[' ' for x in range(self._width)]
                 for y in range(self._height)]
        for (x, y) in screen:
            field[y][x] = chr(screen[(x, y)])

        if returns == list:
            return field
        else:
            return '\n'.join(map(lambda line: ''.join(line), field))
