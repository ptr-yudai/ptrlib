# https://github.com/ptr-yudai/bunkai_struct (1559ca2)
import ctypes
import io
from collections import OrderedDict

class BunkaiMember(object):
    def __init__(self, name, struct):
        assert isinstance(struct, Struct) \
            or isinstance(struct, BitStruct) \
            or isinstance(struct, BitInt) \
            or isinstance(struct, Array) \
            or isinstance(struct, VariableArray) \
            or isinstance(struct, Union) \
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

    @property
    def size(self):
        size = 0
        for name in self._members:
            size += self._members[name].size
        return size

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

class BitStruct(object):
    def __init__(self, *args):
        self._members = OrderedDict()
        self.bitlen = 0
        for member in args:
            if member.name in self._members:
                raise IndexError(f"Member name '{member.name}' duplicates.")
            if not isinstance(member.struct, BitInt):
                raise ValueError(f"Member '{member.name}' is not BitInt.")
            self.bitlen += member.struct.bitlen
            self._members[member.name] = member.struct

    @property
    def size(self):
        return (self.bitlen + 7 & ~7) // 8

    def __getattr__(self, key):
        return self._members[key]

    def __ge__(self, other):
        assert isinstance(other, str), "Usage: 'name' <= BitStruct(...)"
        return BunkaiMember(other, self)

    def _parse_stream(self, stream):
        res = {}
        data = stream.read((self.bitlen + 7 & ~7) // 8)
        offset = 0
        for name in self._members:
            bitlen = self._members[name].bitlen
            extracted = 0
            for cur in range(0, bitlen):
                i, j = (offset + cur) // 8, (offset + cur) % 8
                extracted |= ((data[i] >> j) & 1) << cur
            extracted = int.to_bytes(extracted, (bitlen+7&~7)//8, 'little')
            offset += bitlen
            res[name] = self._members[name]._parse(extracted)
        return res

class BitInt(object):
    def __init__(self, bitlen):
        self.bitlen = bitlen

    def __ge__(self, other):
        assert isinstance(other, str), "Usage: 'name' <= BitInt(...)"
        return BunkaiMember(other, self)

    @property
    def size(self):
        return (self.bitlen + 7 & ~7) // 8

    def _parse(self, data):
        return int.from_bytes(data, 'little')

class Array(object):
    def __init__(self, length, ty):
        self._length = length
        self._ty = ty

    def __ge__(self, other):
        assert isinstance(other, str), "Usage: 'name' <= Array(...)"
        return BunkaiMember(other, self)

    @property
    def size(self):
        return self._length * self._ty.size

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

    @property
    def size(self):
        raise Exception('Cannot calculate the size of variable array')

    def _parse_stream(self, stream):
        res = []
        while True:
            newval = self._ty._parse_stream(stream)
            if not self._repeat_until(newval, res):
                break
            else:
                res.append(newval)
        return res

class Union(object):
    def __init__(self, *args):
        self._members = args
        self._size = max(map(lambda member: member.size, self._members))

    def __ge__(self, other):
        assert isinstance(other, str), "Usage: 'name' <= Union(...)"
        return BunkaiMember(other, self)

    @property
    def size(self):
        return self._size

    def _parse_stream(self, stream):
        res = {}
        data = stream.read(self.size)
        for member in self._members:
            res[member.name] = member.parse(data)
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

    @property
    def size(self):
        return self._ty.size

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

    @property
    def size(self):
        return ctypes.sizeof(self._ty)

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
    data  = b'\xde\xad\xbe\xef' # magic
    data += b'fizzbuzz\0'       # name
    data += b'\x72\x01'         # version
    data += b'\x11\xf0' + b'\x33\xf1' # children
    data += b'\xff\xff\xff\xff\xff\xff\xff\xff' + b'\x01' # v1_data
    my_struct = 'MyStruct' <= Struct(
        'magic' <= u32be,
        'name' <= VariableArray(lambda c,_: c!=0, s8),
        'version' <= BitStruct(
            'major' <= BitInt(4),
            'minor' <= BitInt(4),
            'is_beta' <= BitInt(1),
        ),
        'children' <= Array(
            2,
            Struct(
                'x' <= Enum(u8, CHILD_X1=0x11, CHILD_X2=0x22, CHILD_X3=0x33),
                'y' <= Enum(u8, ['CHILD_Y1', 'CHILD_Y2'], startsfrom=0xf0),
            )
        ),
        'data' <= Union(
            'v1_data' <= Struct(
                'value' <= s32,
                'flag'  <= u8,
            ),
            'v2_data' <= Struct(
                'value' <= s64,
                'flag'  <= u8,
            ),
        )
    )

    print(my_struct.parse(data))
