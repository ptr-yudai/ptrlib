import contextlib
from typing import BinaryIO
from .byteconv import str2bytes
from ptrlib.console.color import Color


def hexdump(data: str | bytes,
            base: int = 0,
            file: BinaryIO | None = None,
            *,
            color: bool = True,
            color_ascii: str = Color.BRIGHT_BLUE,
            color_nonascii: str = Color.BRIGHT_CYAN,
            color_null: str = Color.WHITE,
            collapse_repeats: bool = True,
            prefix: str = '',
            postfix: str = '') -> None:
    """Print (or append) a classic hexdump.

    - 16 bytes per line: hex bytes grouped 8+8, then ASCII gutter.
    - Repeated consecutive lines are collapsed to a single '*' when
      ``collapse_repeats=True`` (default). Set it to ``False`` to show all lines.
    - If ``file`` is provided (binary stream), lines are appended to that file
      instead of being printed to stdout.
    - If ``color=True``, both the HEX area and ASCII gutter are colored:
        * printable (0x20..0x7e): **cyan**
        * NUL (0x00): **black/gray**
        * others: **standard** (no color)

    Args:
        data: Bytes (or str; converted via ``str2bytes``) to dump.
        base: Starting offset shown at the left.
        file: Binary file-like object to append lines to (opened for writing).
        color: Enable colorized output (requires ``Color`` constants).
        collapse_repeats: Collapse identical consecutive rows into a single '*'.
        prefix: String prepended to each output line.
        postfix: String appended to each output line.
    """
    if isinstance(data, str):
        data = str2bytes(data)
    b = memoryview(bytes(data))

    def emit(line: str) -> None:
        if file is None:
            print(line)
        else:
            file.write(line.encode("utf-8") + b"\n")  # type: ignore[arg-type]
            with contextlib.suppress(Exception):
                file.flush()

    last_chunk: bytes | None = None
    in_omission = False

    for off in range(0, len(b), 16):
        chunk = b[off:off + 16].tobytes()

        # Collapse identical consecutive lines
        if collapse_repeats and last_chunk is not None and chunk == last_chunk:
            if not in_omission:
                emit(f"{prefix}*{postfix}")
                in_omission = True
            continue
        in_omission = False
        last_chunk = chunk

        # Address
        addr = f"{base + off:08x}"

        # HEX columns (16 tokens; pad missing bytes; 8+8 grouping)
        hex_tokens: list[str] = []
        for i in range(16):
            if i < len(chunk):
                byte = chunk[i]
                h = f"{byte:02x}"
                if color:
                    if 0x20 <= byte <= 0x7e:
                        h = f"{color_ascii}{h}{Color.END}"
                    elif byte == 0x00:
                        h = f"{color_null}{h}{Color.END}"
                    else:
                        h = f"{color_nonascii}{h}{Color.END}"
                hex_tokens.append(h)
            else:
                # two spaces to keep alignment of a missing byte
                hex_tokens.append("  ")
        hex_cols = " ".join(hex_tokens[:8]) + "  " + " ".join(hex_tokens[8:])

        # ASCII gutter (build plain 16-char string first to keep alignment)
        raw_ascii = "".join(chr(c) if 0x20 <= c <= 0x7e else "." for c in chunk).ljust(16)

        if not color:
            ascii_gutter = raw_ascii
        else:
            chars: list[str] = []
            for i in range(16):
                if i >= len(chunk):
                    chars.append(raw_ascii[i])  # padding
                    continue
                byte = chunk[i]
                ch = raw_ascii[i]
                if 0x20 <= byte <= 0x7e:
                    chars.append(f"{color_ascii}{ch}{Color.END}")
                elif byte == 0x00:
                    chars.append(f"{color_null}{ch}{Color.END}")
                else:
                    chars.append(f"{color_nonascii}{ch}{Color.END}")
            ascii_gutter = "".join(chars)

        emit(f"{prefix}{addr}  {hex_cols}  |{ascii_gutter}|{postfix}")


__all__ = ["hexdump"]
