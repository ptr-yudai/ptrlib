"""This packages provides binary struct parser.

This code is a copy of https://github.com/ptr-yudai/bunkai_struct (1559ca2)
"""
import ctypes
import io
from abc import ABCMeta, abstractmethod
from collections import OrderedDict
from typing import Any, BinaryIO, Callable, List, Optional, Union as TypingUnion


BunkaiStructT = TypingUnion[
    'Struct', 'BitStruct', 'BitInt', 'Array', 'VariableArray',
    'Union', 'Enum', 'BunkaiPrimitive'
]


class BunkaiMember:
    """Simple member parser

    Args:
        name (str): The name of this member.
        struct (BunkaiStructT): The struct corresponding to this member.
    """
    def __init__(self, name: str, struct: BunkaiStructT):
        assert isinstance(struct, (
            Struct, BitStruct, BitInt, Array, VariableArray, Union, Enum, BunkaiPrimitive
        ))
        self.name = name
        """The name of this member."""
        self.struct = struct
        """The struct corresponding to this member."""

    def __getattr__(self, key):
        return getattr(self.struct, key)

    def parse(self, data: bytes):
        """Parse from bytes.
        """
        return self.parse_stream(io.BytesIO(data))

    def parse_stream(self, stream: BinaryIO):
        """Parse from a stream

        Args:
            stream (BinaryIO): A stream to receive data from.
        """
        return self.struct.parse_stream(stream)

class BunkaiStructBase(metaclass=ABCMeta):
    """An abstract class for structs.
    """
    @property
    @abstractmethod
    def size(self) -> int:
        """Get the size of this struct.
        """

    @abstractmethod
    def parse_stream(self, stream: BinaryIO) -> Any:
        """Parse from a stream.

        Args:
            stream (BinaryIO): A stream to receive data from.
        """

    @abstractmethod
    def __getattr__(self, key: str) -> BunkaiStructT:
        """Get a member

        Args:
            key (str): The name of the member to look up.
        """

    @abstractmethod
    def __ge__(self, other: str) -> BunkaiMember:
        """Generate a :obj:`BunkaiMember`

        Args:
            other (str): The name of the member.
        """

class Struct(BunkaiStructBase):
    """A class representing a struct.
    """
    def __init__(self, *args: BunkaiMember):
        self._members: OrderedDict[str, BunkaiStructT] = OrderedDict()
        for member in args:
            if member.name in self._members:
                raise IndexError(f"Member name '{member.name}' duplicates.")
            self._members[member.name] = member.struct

    @property
    def size(self) -> int:
        size = 0
        for name in self._members:
            size += self._members[name].size
        return size

    def parse_stream(self, stream: BinaryIO) -> Any:
        res = {}
        for name in self._members:
            res[name] = self._members[name].parse_stream(stream)
        return res

    def __getattr__(self, key: str) -> BunkaiStructT:
        return self._members[key]

    def __ge__(self, other: str) -> BunkaiMember:
        assert isinstance(other, str), "Usage: 'name' <= Struct(...)"
        return BunkaiMember(other, self)

class BitStruct(BunkaiStructBase):
    """A class representing a struct containing bit fields.

    Args:
        *args: Struct members. Each member must be a :obj:`BitInt`.

    Examples:
        ```
        'CR3Register' <= BitStruct(
            'reserved1' <= BitInt(3),
            'PWT' <= BitInt(1),
            'PCD' <= BitInt(1),
            'reserved2' <= BitInt(7),
            'PDBR' <= BitInt(52),
        )
        ```
    """
    def __init__(self, *args: BunkaiMember):
        self._members: OrderedDict[str, BitInt] = OrderedDict()
        self.bitlen = 0
        for member in args:
            if member.name in self._members:
                raise IndexError(f"Member name '{member.name}' duplicates.")
            if not isinstance(member.struct, BitInt):
                raise ValueError(f"Member '{member.name}' is not BitInt.")
            self.bitlen += member.struct.bitlen
            self._members[member.name] = member.struct

    @property
    def size(self) -> int:
        return (self.bitlen + 7 & ~7) // 8

    def parse_stream(self, stream: BinaryIO) -> Any:
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
            res[name] = self._members[name].parse(extracted)
        return res

    def __getattr__(self, key: str) -> BunkaiStructT:
        return self._members[key]

    def __ge__(self, other: str) -> BunkaiMember:
        assert isinstance(other, str), "Usage: 'name' <= BitStruct(...)"
        return BunkaiMember(other, self)

class BitInt(BunkaiStructBase):
    """A class representing a bit field.
    """
    def __init__(self, bitlen: int):
        self.bitlen = bitlen

    @property
    def size(self) -> int:
        return (self.bitlen + 7 & ~7) // 8

    def parse(self, data: bytes) -> int:
        """Parse from bytes.

        Args:
            data (bytes): The bytes to parse.

        Returns:
            int: The parsed value.
        """
        return int.from_bytes(data, 'little')

    def parse_stream(self, stream: BinaryIO) -> Any:
        raise NotImplementedError("BitInt is not supposed to read a stream")

    def __getattr__(self, key: str):
        raise NotImplementedError("BunkaiPrimitive does not have a member")

    def __ge__(self, other: str) -> BunkaiMember:
        assert isinstance(other, str), "Usage: 'name' <= BitInt(...)"
        return BunkaiMember(other, self)

class Array(BunkaiStructBase):
    """A class representing an array.
    """
    def __init__(self, length: int, ty: BunkaiStructT):
        self._length = length
        self._ty = ty

    @property
    def size(self) -> int:
        return self._length * self._ty.size

    def parse_stream(self, stream: BinaryIO) -> Any:
        res = []
        for _ in range(self._length):
            res.append(self._ty.parse_stream(stream))
        return res

    def __getattr__(self, key: str):
        raise NotImplementedError("BunkaiPrimitive does not have a member")

    def __ge__(self, other: str) -> BunkaiMember:
        assert isinstance(other, str), "Usage: 'name' <= Array(...)"
        return BunkaiMember(other, self)

class VariableArray(BunkaiStructBase):
    """A class representing a variable-length array.
    """
    def __init__(self,
                 repeat_until: Callable[[Any, List[Any]], bool],
                 ty: BunkaiStructT):
        self._repeat_until = repeat_until
        self._ty = ty

    @property
    def size(self):
        raise NotImplementedError('Cannot calculate the size of variable array')

    def parse_stream(self, stream: BinaryIO) -> Any:
        res = []
        while True:
            newval = self._ty.parse_stream(stream)
            if not self._repeat_until(newval, res):
                break
            res.append(newval)
        return res

    def __getattr__(self, key: str):
        raise NotImplementedError("BunkaiPrimitive does not have a member")

    def __ge__(self, other) -> BunkaiMember:
        assert isinstance(other, str), "Usage: 'name' <= VariableArray(...)"
        return BunkaiMember(other, self)

class Union(BunkaiStructBase):
    """A class representing a union struct.
    """
    def __init__(self, *args: BunkaiMember):
        self._members = args
        self._size = max(map(lambda member: member.size, self._members))

    @property
    def size(self) -> int:
        """Get the size of this struct.
        """
        return self._size

    def parse_stream(self, stream: BinaryIO) -> Any:
        """Parse from a stream.

        Args:
            stream (BinaryIO): A stream to receive data from.

        Returns:
            Parsed members in a dictionary.
        """
        res = {}
        data = stream.read(self.size)
        for member in self._members:
            res[member.name] = member.parse(data)
        return res

    def __getattr__(self, key: str):
        raise NotImplementedError("BunkaiPrimitive does not have a member")

    def __ge__(self, other) -> BunkaiMember:
        assert isinstance(other, str), "Usage: 'name' <= Union(...)"
        return BunkaiMember(other, self)

class Enum(BunkaiStructBase):
    """A class representing an enum type.
    """
    def __init__(self,
                 ty: Any,
                 members: Optional[List[str]] = None,
                 startsfrom: Optional[int] = None,
                 **kwargs: Any):
        self._ty = ty
        self._items = {}

        if members is not None:
            if startsfrom is None:
                startsfrom = 0
            for i, k in enumerate(members):
                v = startsfrom + i
                if v in self._items.values():
                    raise ValueError(f"Duplicated Enum value: {v}")
                self._items[k] = v

        else:
            for k, v in kwargs.items():
                if v in self._items.values():
                    raise ValueError(f"Duplicated Enum value: {v}")
                self._items[k] = v

    @property
    def size(self) -> int:
        """Get the size of this struct.
        """
        return self._ty.size

    def parse_stream(self, stream: BinaryIO) -> Any:
        """
        Returns:
            The name of the enum type, or a raw integer value
            if the value does not match any of the enum types.
        """
        data = self._ty.parse_stream(stream)
        for k, v in self._items.items():
            if v == data:
                return k
        return data

    def __getattr__(self, key: str):
        raise NotImplementedError("BunkaiPrimitive does not have a member")

    def __ge__(self, other):
        assert isinstance(other, str), "Usage: 'name' <= Enum(...)"
        return BunkaiMember(other, self)

class BunkaiPrimitive(BunkaiStructBase):
    """Primitive data struct
    """
    def __init__(self, ty: Any, is_bigendian: bool=False):
        self._ty = ty
        self._is_bigendian = is_bigendian

    @property
    def size(self) -> int:
        return ctypes.sizeof(self._ty)

    def parse_stream(self, stream: BinaryIO) -> Any:
        """Parse from a stream.

        Args:
            stream (BinaryIO): A binary stream to receive data from.

        Return:
            int: A parsed value.
        """
        size = ctypes.sizeof(self._ty)
        buf = stream.read(size)
        if len(buf) != size:
            raise EOFError("File truncated")

        if self._is_bigendian:
            return self._ty.from_buffer_copy(buf[::-1]).value

        return self._ty.from_buffer_copy(buf).value

    def __call__(self, *args: int):
        return self._ty(*args)

    def __getattr__(self, key: str):
        raise NotImplementedError("BunkaiPrimitive does not have a member")

    def __ge__(self, other):
        assert isinstance(other, str), "Usage: 'name' <= Primitive(...)"
        return BunkaiMember(other, self)


u8  = BunkaiPrimitive(ctypes.c_uint8)
u16 = BunkaiPrimitive(ctypes.c_uint16)
u32 = BunkaiPrimitive(ctypes.c_uint32)
u64 = BunkaiPrimitive(ctypes.c_uint64)
s8  = BunkaiPrimitive(ctypes.c_int8)
s16 = BunkaiPrimitive(ctypes.c_int16)
s32 = BunkaiPrimitive(ctypes.c_int32)
s64 = BunkaiPrimitive(ctypes.c_int64)
u8be  = BunkaiPrimitive(ctypes.c_uint8, True)
u16be = BunkaiPrimitive(ctypes.c_uint16, True)
u32be = BunkaiPrimitive(ctypes.c_uint32, True)
u64be = BunkaiPrimitive(ctypes.c_uint64, True)
s8be  = BunkaiPrimitive(ctypes.c_int8, True)
s16be = BunkaiPrimitive(ctypes.c_int16, True)
s32be = BunkaiPrimitive(ctypes.c_int32, True)
s64be = BunkaiPrimitive(ctypes.c_int64, True)

__all__ = [
    'u8', 'u16', 'u32', 'u64', 's8', 's16', 's32', 's64',
    'u8be', 'u16be', 'u32be', 'u64be', 's8be', 's16be', 's32be', 's64be',
    'BunkaiPrimitive', 'BunkaiMember',
    'Enum', 'Union', 'Array', 'VariableArray', 'Struct', 'BitStruct', 'BitInt'
]


if __name__ == '__main__':
    DATA  = b'\xde\xad\xbe\xef' # magic
    DATA += b'fizzbuzz\0'       # name
    DATA += b'\x72\x01'         # version
    DATA += b'\x11\xf0' + b'\x33\xf1' # children
    DATA += b'\xff\xff\xff\xff\xff\xff\xff\xff' + b'\x01' # v1_data
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

    print(my_struct.parse(DATA))
