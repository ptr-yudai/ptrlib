import builtins
from logging import getLogger
import struct
from typing import Type, TypeVar, Union, overload
try:
    from typing import Literal
except:
    from typing_extensions import Literal
from ptrlib.binary.encoding.byteconv import str2bytes

logger = getLogger(__name__)

_T = TypeVar("_T", int, float)

def u8(data: Union[str, bytes], signed: bool=False) -> int:
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        raise ValueError("u8: {} given ('bytes' expected)".format(type(data)))

    return int.from_bytes(data, 'big', signed=signed)

def u16(data: Union[str, bytes], byteorder: Literal["little", "big"]='little', signed: bool=False) -> int:
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        raise ValueError("u16: {} given ('bytes' expected)".format(type(data)))

    return int.from_bytes(data, byteorder=byteorder, signed=signed)

@overload
def u32(data: Union[str, bytes], byteorder: Literal["little", "big"]="little", signed: bool=False, result_type: Type[int]=int) -> int: ...

@overload
def u32(data: Union[str, bytes], byteorder: Literal["little", "big"]="little", signed: bool=False, result_type: Type[float]=float) -> float: ...

def u32(data: Union[str, bytes], byteorder: Literal["little", "big"]='little', signed: bool=False, result_type: Type[_T]=int) -> _T:
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        raise ValueError("u32: {} given ('bytes' expected)".format(type(data)))

    if result_type == float:
        logger.warning("u32(v, type=...) is deprecated. Use u32f(v) instead.")
        return struct.unpack(
            '{}f'.format('<' if byteorder == 'little' else '>'),
            data
        )[0]
    
    return int.from_bytes(data, byteorder=byteorder, signed=signed)

def u32f(data: Union[str, bytes], byteorder: Literal["little", "big"]="little"):
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        raise ValueError("u32f: {} given ('bytes' expected)".format(builtins.type(data)))

    return struct.unpack(
        '{}f'.format('<' if byteorder == 'little' else '>'),
        data
    )[0]

@overload
def u64(data: Union[str, bytes], byteorder: Literal["little", "big"]="little", signed: bool=False, type: Type[int]=int) -> int: ...

@overload
def u64(data: Union[str, bytes], byteorder: Literal["little", "big"]="little", signed: bool=False, type: Type[float]=float) -> float: ...

def u64(data: Union[str, bytes], byteorder: Literal["little", "big"]='little', signed: bool=False, type: Type[_T]=int) -> _T:
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        raise ValueError("u64: {} given ('bytes' expected)".format(builtins.type(data)))

    if type == float:
        logger.warning("u64(v, type=...) is deprecated. Use u64f(v) instead.")
        return struct.unpack(
            '{}d'.format('<' if byteorder == 'little' else '>'),
            data
        )[0]

    return int.from_bytes(data, byteorder=byteorder, signed=signed)

def u64f(data: Union[str, bytes], byteorder: Literal["little", "big"]="little"):
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        raise ValueError("u64f: {} given ('bytes' expected)".format(builtins.type(data)))

    return struct.unpack(
        '{}d'.format('<' if byteorder == 'little' else '>'),
        data
    )[0]
