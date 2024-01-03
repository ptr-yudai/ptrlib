import functools
import re

try:
    cache = functools.cache
except AttributeError:
    cache = functools.lru_cache


@cache
def _escape_codes():
    codes = {}
    # Cursor
    codes['CSI_CURSOR_MOVE']   = re.compile(b'^\x1b\[([1-9]\d*);([1-9]\d*)[Hf]')
    codes['CSI_CURSOR_ROW']    = re.compile(b'^\x1b\[([1-9]\d*)d')
    codes['CSI_CURSOR_COLUMN'] = re.compile(b'^\x1b\[([1-9]\d*)[`G]')
    codes['CSI_CURSOR_UP']    = re.compile(b'^\x1b\[(\d*)A')
    codes['CSI_CURSOR_DOWN']  = re.compile(b'^\x1b\[(\d*)B')
    codes['CSI_CURSOR_RIGHT'] = re.compile(b'^\x1b\[(\d*)C')
    codes['CSI_CURSOR_LEFT']  = re.compile(b'^\x1b\[(\d*)D')
    codes['CSI_CURSOR_UP_HEAD']   = re.compile(b'^\x1b\[(\d*)F')
    codes['CSI_CURSOR_DOWN_HEAD'] = re.compile(b'^\x1b\[(\d*)E')
    codes['CSI_CURSOR_SAVE']    = re.compile(b'^\x1b\[s')
    codes['CSI_CURSOR_RESTORE'] = re.compile(b'^\x1b\[u')
    codes['CSI_CURSOR_REQUEST'] = re.compile(b'^\x1b\[6n')
    codes['FP_CURSOR_SAVE']    = re.compile(b'^\x1b7')
    codes['FP_CURSOR_RESTORE'] = re.compile(b'^\x1b8')
    codes['FE_CURSOR_ONEUP'] = re.compile(b'^\x1bM')

    # Character
    codes['CSI_CHAR_REPEAT'] = re.compile(b'^\x1b\[(\d+)b')

    # Erase 
    codes['CSI_ERASE_DISPLAY_FORWARD']  = re.compile(b'^\x1b\[[0]J')
    codes['CSI_ERASE_DISPLAY_BACKWARD'] = re.compile(b'^\x1b\[1J')
    codes['CSI_ERASE_DISPLAY_ALL']      = re.compile(b'^\x1b\[2J')
    codes['CSI_ERASE_LINE_FORWARD']  = re.compile(b'^\x1b\[[0]K')
    codes['CSI_ERASE_LINE_BACKWARD'] = re.compile(b'^\x1b\[1K')
    codes['CSI_ERASE_LINE_ALL']      = re.compile(b'^\x1b\[2K')

    # Others
    codes['CSI_COLOR'] = re.compile(b'^\x1b\[(\d+)m')
    codes['CSI_MODE']         = re.compile(b'^\x1b\[=(\d+)[hl]')
    codes['CSI_PRIVATE_MODE'] = re.compile(b'^\x1b\[?(\d+)[hl]')

    return codes


def draw_ansi(buf: bytes):
    """Interpret ANSI code sequences to screen

    Args:
        buf (bytes): ANSI code sequences

    Returns:
       list: 2D array of screen to be drawn
    """
    draw = []
    E = _escape_codes()
    width = height = x = y = 0
    saved_dec = saved_sco = None
    while len(buf):
        if buf[0] == 13: # \r
            x = 0
            buf = buf[1:]
            continue

        elif buf[0] == 10: # \n
            x = 0
            y += 1
            buf = buf[1:]
            continue

        elif buf[0] != 0x1b:
            if x >= width: width = x + 1
            if y >= height: height = y + 1
            draw.append(('PUTCHAR', x, y, buf[0]))
            x += 1
            buf = buf[1:]
            continue

        # CSI sequences
        if m := E['CSI_CURSOR_MOVE'].match(buf):
            y, x = int(m.group(1)) - 1, int(m.group(2)) - 1
        elif m := E['CSI_CURSOR_ROW'].match(buf):
            y = int(m.group(1)) - 1
        elif m := E['CSI_CURSOR_COLUMN'].match(buf):
            x = int(m.group(1)) - 1
        elif m := E['CSI_CURSOR_UP'].match(buf):
            y = max(0, y - int(m.group(1))) if m.group(1) else max(0, y-1)
        elif m := E['CSI_CURSOR_DOWN'].match(buf):
            y += int(m.group(1)) if m.group(1) else 1
        elif m := E['CSI_CURSOR_LEFT'].match(buf):
            x = max(0, x - int(m.group(1))) if m.group(1) else max(0, x-1)
        elif m := E['CSI_CURSOR_RIGHT'].match(buf):
            x += int(m.group(1)) if m.group(1) else 1
        elif m := E['CSI_CURSOR_UP_HEAD'].match(buf):
            x, y = 0, max(0, y - int(m.group(1))) if m.group(1) else max(0, y-1)
        elif m := E['CSI_CURSOR_DOWN_HEAD'].match(buf):
            x, y = 0, y + int(m.group(1)) if m.group(1) else y+1
        elif m := E['CSI_CURSOR_SAVE'].match(buf):
            saved_sco = (x, y)
        elif m := E['CSI_CURSOR_RESTORE'].match(buf):
            if saved_sco is not None: x, y = saved_sco
        elif m := E['CSI_CURSOR_REQUEST'].match(buf):
            pass # Not implemented: Request cursor position
        elif m := E['CSI_COLOR'].match(buf):
            pass # Not implemented: Change color
        elif m := E['CSI_MODE'].match(buf):
            pass # Not implemented: Set mode

        # Repease character
        elif m := E['CSI_CHAR_REPEAT'].match(buf):
            n = int(m.group(1))
            draw.append(('CSI_CHAR_REPEAT', x, y, n))
            x += n

        # Fe escape sequences
        elif m := E['FE_CURSOR_ONEUP'].match(buf):
            y = max(0, y - 1) # scroll not implemented

        # Fp escape sequences
        elif m := E['FP_CURSOR_SAVE'].match(buf):
            saved_dec = (x, y)
        elif m := E['FP_CURSOR_RESTORE'].match(buf):
            if saved_dec is not None: x, y = saved_dec

        # Operation
        else:
            for k in ['CSI_ERASE_DISPLAY_FORWARD',
                      'CSI_ERASE_DISPLAY_BACKWARD',
                      'CSI_ERASE_DISPLAY_ALL',
                      'CSI_ERASE_LINE_FORWARD',
                      'CSI_ERASE_LINE_BACKWARD',
                      'CSI_ERASE_LINE_ALL']:
                if m := E[k].match(buf):
                    if k == 'CSI_ERASE_DISPLAY_ALL':
                        draw = []
                    else:
                        draw.append((k, x, y, None))
                    break

        # Otherwise draw text
        if m:
            buf = buf[m.end():]
        else:
            # TODO: skip ESC only?
            raise NotImplementedError(f"Could not interpret code: {buf[:10]}")

    # Emualte drawing
    screen = [[' ' for x in range(width)] for y in range(height)]
    last_char = ' '
    for op, x, y, attr in draw:
        if op == 'PUTCHAR':
            last_char = chr(attr)
            screen[y][x] = last_char

        elif op == 'CSI_CHAR_REPEAT':
            for j in range(attr):
                screen[y][x+j] = last_char

        elif op == 'CSI_ERASE_DISPLAY_FORWARD':
            for j in range(x, width):
                screen[y][j] = ' '
            for i in range(y+1, height):
                for j in range(width):
                    screen[i][j] = ' '

        elif op == 'CSI_ERASE_DISPLAY_BACKWARD':
            for j in range(x):
                screen[y][j] = ' '
            for i in range(y):
                for j in range(width):
                    screen[i][j] = ' '

        elif op == 'CSI_ERASE_DISPLAY_ALL':
            for i in range(height):
                for j in range(width):
                    screen[i][j] = ' '

        elif op == 'CSI_ERASE_LINE_FORWARD':
            for j in range(x, width):
                screen[y][j] = ' '

        elif op == 'CSI_ERASE_LINE_BACKWARD':
            for j in range(x):
                screen[y][j] = ' '

        elif op == 'CSI_ERASE_LINE_ALL':
            for j in range(width):
                screen[y][j] = ' '

    return screen
