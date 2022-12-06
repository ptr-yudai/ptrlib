import ctypes
import io
from collections import OrderedDict

class BunkaiMember(object):
    def __init__(self, name, struct):
        assert isinstance(struct, Struct) \
            or isinstance(struct, Array) \
            or isinstance(struct, VariableArray) \
            or isinstance(struct, Enum) \
            or isinstance(struct, BunkaiPrimitive)
        self.name = name
        self.struct = struct

    def __getattr__(self, key):
        return getattr(self.struct, key)

    def parse(self, data):
        return self.parse_stream(io.BytesIO(data))

    def parse_stream(self, stream):
        return self.struct._parse_stream(stream)

class Struct(object):
    def __init__(self, *args):
        self._members = OrderedDict()
        for member in args:
            if member.name in self._members:
                raise IndexError(f"Member name '{member.name}' duplicates.")
            self._members[member.name] = member.struct

    def __getattr__(self, key):
        return self._members[key]

    def __ge__(self, other):
        assert isinstance(other, str), "Usage: 'name' <= Struct(...)"
        return BunkaiMember(other, self)

    def _parse_stream(self, stream):
        res = {}
        for name in self._members:
            res[name] = self._members[name]._parse_stream(stream)
        return res

class Array(object):
    def __init__(self, length, ty):
        self._length = length
        self._ty = ty

    def __ge__(self, other):
        assert isinstance(other, str), "Usage: 'name' <= Array(...)"
        return BunkaiMember(other, self)

    def _parse_stream(self, stream):
        res = []
        for _ in range(self._length):
            res.append(self._ty._parse_stream(stream))
        return res

class VariableArray(object):
    def __init__(self, repeat_until, ty):
        self._repeat_until = repeat_until
        self._ty = ty

    def __ge__(self, other):
        assert isinstance(other, str), "Usage: 'name' <= VariableArray(...)"
        return BunkaiMember(other, self)

    def _parse_stream(self, stream):
        res = []
        while True:
            newval = self._ty._parse_stream(stream)
            if not self._repeat_until(newval, res):
                break
            else:
                res.append(newval)
        return res

class Enum(object):
    def __init__(self, ty, members=None, startsfrom=None, **kwargs):
        self._ty = ty
        self._items = {}

        if members is not None:
            if startsfrom is None:
                startsfrom = 0
            for i, k in enumerate(members):
                v = startsfrom + i
                if v in self._items.values(): # TODO: Performance?
                    raise ValueError("Duplicated Enum value: {}".format(v))
                self._items[k] = v
        else:
            for k in kwargs:
                v = kwargs[k]
                if v in self._items.values(): # TODO: Performance?
                    raise ValueError("Duplicated Enum value: {}".format(v))
                self._items[k] = v

    def __ge__(self, other):
        assert isinstance(other, str), "Usage: 'name' <= Enum(...)"
        return BunkaiMember(other, self)

    def _parse_stream(self, stream):
        v = self._ty._parse_stream(stream)
        for k in self._items:
            if self._items[k] == v:
                return k
        return v

class BunkaiPrimitive(object):
    def __init__(self, ty, is_bigendian=False):
        self._ty = ty
        self._is_bigendian = is_bigendian

    def __call__(self, *args):
        return self._ty(*args)

    def __ge__(self, other):
        assert isinstance(other, str), "Usage: 'name' <= Primitive(...)"
        return BunkaiMember(other, self)

    def _parse_stream(self, stream):
        size = ctypes.sizeof(self._ty)
        buf = stream.read(size)
        if len(buf) != size:
            raise EOFError("File truncated")

        if self._is_bigendian:
            return self._ty.from_buffer_copy(buf[::-1]).value
        else:
            return self._ty.from_buffer_copy(buf).value

u8  = BunkaiPrimitive(ctypes.c_ubyte)
u16 = BunkaiPrimitive(ctypes.c_ushort)
u32 = BunkaiPrimitive(ctypes.c_uint)
u64 = BunkaiPrimitive(ctypes.c_ulong)
s8  = BunkaiPrimitive(ctypes.c_byte)
s16 = BunkaiPrimitive(ctypes.c_short)
s32 = BunkaiPrimitive(ctypes.c_int)
s64 = BunkaiPrimitive(ctypes.c_long)
u8be  = BunkaiPrimitive(ctypes.c_ubyte, True)
u16be = BunkaiPrimitive(ctypes.c_ushort, True)
u32be = BunkaiPrimitive(ctypes.c_uint, True)
u64be = BunkaiPrimitive(ctypes.c_ulong, True)
s8be  = BunkaiPrimitive(ctypes.c_byte, True)
s16be = BunkaiPrimitive(ctypes.c_short, True)
s32be = BunkaiPrimitive(ctypes.c_int, True)
s64be = BunkaiPrimitive(ctypes.c_long, True)

if __name__ == '__main__':
    Elf_Ehdr = 'Elf_Ehdr' <= Struct(
        'e_ident' <= Struct(
            'EI_MSG'   <= Array(4, s8),
            'EI_CLASS' <= Enum(s8, HOGE=1, HUGA=2),
        ),
        'hoge' <= u32,
    )

    with open("/bin/cat", "rb") as f:
        print(Elf_Ehdr.parse_stream(f))

    hoge = 'hoge' <= Array(3, s32)
    print(hoge.parse(b"A"*8 + b"\xff"*8))

    cstr = 's' <= VariableArray(lambda c,_: c!=0, s8)
    print(cstr.parse(b"fizzbuzz\x00foobar\x00123234"))
