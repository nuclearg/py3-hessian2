from email.contentmanager import raw_data_manager

from datetime import datetime
import time
from struct import pack, unpack
from typing import Any, List

try:
    import py3_hessian2_rsimpl
except ImportError:
    pass

"""
Hessian 2.0 Protocol

see http://hessian.caucho.com/doc/hessian-serialization.html

Hessian Bytecode map:
    x00 - x1f    # utf-8 string length 0-32
    x20 - x2f    # binary data length 0-16
    x30 - x33    # utf-8 string length 0-1023
    x34 - x37    # binary data length 0-1023
    x38 - x3f    # three-octet compact long (-x40000 to x3ffff)
    x40          # reserved (expansion/escape)
    x41          # 8-bit binary data non-final chunk ('A')
    x42          # 8-bit binary data final chunk ('B')
    x43          # object type definition ('C')
    x44          # 64-bit IEEE encoded double ('D')
    x45          # reserved
    x46          # boolean false ('F')
    x47          # reserved
    x48          # untyped map ('H')
    x49          # 32-bit signed integer ('I')
    x4a          # 64-bit UTC millisecond date ('J')
    x4b          # 32-bit UTC minute date ('K')
    x4c          # 64-bit signed long integer ('L')
    x4d          # map with type ('M')
    x4e          # null ('N')
    x4f          # object instance ('O')
    x50          # reserved
    x51          # reference to map/list/object - integer ('Q')
    x52          # utf-8 string non-final chunk ('R')
    x53          # utf-8 string final chunk ('S')
    x54          # boolean true ('T')
    x55          # variable-length list/vector ('U')
    x56          # fixed-length list/vector ('V')
    x57          # variable-length untyped list/vector ('W')
    x58          # fixed-length untyped list/vector ('X')
    x59          # long encoded as 32-bit int ('Y')
    x5a          # list/map terminator ('Z')
    x5b          # double 0.0
    x5c          # double 1.0
    x5d          # double represented as byte (-128.0 to 127.0)
    x5e          # double represented as short (-32768.0 to 32767.0)
    x5f          # double represented as float
    x60 - x6f    # object with direct type
    x70 - x77    # fixed list with direct length
    x78 - x7f    # fixed untyped list with direct length
    x80 - xbf    # one-octet compact int (-x10 to x3f, x90 is 0)
    xc0 - xcf    # two-octet compact int (-x800 to x7ff)
    xd0 - xd7    # three-octet compact int (-x40000 to x3ffff)
    xd8 - xef    # one-octet compact long (-x8 to xf, xe0 is 0)
    xf0 - xff    # two-octet compact long (-x800 to x7ff, xf8 is 0)
"""


def hessian2_dumps(v: Any, **kwargs) -> bytes:
    """
    将一个对象按照 hessian 序列化协议转换为字节数组

    其中，对象的类型使用 #class 表示，例：
    {
        '#class': 'com.test.TestBean',
        'a': 1,
        'b': '2',
        'c': [{
            '#class': 'com.test.TestBean',
            'a': 3,
            'b': '4',
        },{
            '#class': 'com.test.TestBean',
            'a': 5,
            'b': '6',
        }]
    }
    """
    # if py3_hessian2_rsimpl:
    #     return py3_hessian2_rsimpl.hessian2_dumps(v)

    serializer = Hessian2Serializer()
    serializer.write(v)
    return serializer.export()


def hessian2_loads(data: bytes, *, assuming_x34_as_bytes: bool = False, **kwargs) -> Any:
    """
    将字节数组按照 hessian 序列化协议转换为对象

    java 侧的对象类型使用 #class 字段表示，例：
    {
        '#class': 'com.test.TestBean',
        'a': 1,
        'b': '2',
        'c': [{
            '#class': 'com.test.TestBean',
            'a': 3,
            'b': '4',
        },{
            '#class': 'com.test.TestBean',
            'a': 5,
            'b': '6',
        }]
    }
    """
    # if py3_hessian2_rsimpl:
    #     return py3_hessian2_rsimpl.hessian2_loads(data)

    return Hessian2Deserializer(data).read()


class Hessian2Serializer:

    def __init__(self, **kwargs):
        self._bytes: bytearray = bytearray()
        self._refs: Dict[str, int] = {}  # key 是对象 id
        self._class_definitions: Dict[str, int] = {}
        self._type_names: Dict[str, int] = {}

    def export(self) -> bytes:
        return bytes(self._bytes)

    def write(self, v: Any) -> None:
        if v is None:
            self.write_null()
        elif isinstance(v, bool):
            self.write_boolean(v)
        elif isinstance(v, int):
            self.write_int(v)
        elif isinstance(v, float):
            self.write_float(v)
        elif isinstance(v, str):
            self.write_string(v)
        elif isinstance(v, bytes):
            self.write_bytes(v)
        elif isinstance(v, datetime):
            self.write_datetime(v)
        elif isinstance(v, list):
            self.write_list(v)
        elif isinstance(v, dict):
            self.write_map(v)
        else:
            raise ValueError('unsupported type: %s' % type(v))

    def write_null(self) -> None:
        # null ::= 'N'
        self._bytes.append(0x4e)  # 'N'

    def write_boolean(self, v: bool) -> None:
        # boolean ::= 'T'
        #         ::= 'F'
        self._bytes.append(0x54 if v else 0x46)  # 'T' or 'F'

    def write_int(self, v: int, force_long: bool = False) -> None:
        # int ::= 'I' b3 b2 b1 b0
        #     ::= [x80-xbf]          # -x10 to x3f
        #     ::= [xc0-xcf] b0       # -x800 to x7ff
        #     ::= [xd0-xd7] b1 b0    # -x40000 to x3ffff
        # long ::= 'L' b7 b6 b5 b4 b3 b2 b1 b0
        #      ::= [xd8-xef]         # -x08 to x0f
        #      ::= [xf0-xff] b0      # -x800 to x7ff
        #      ::= [x38-x3f] b1 b0   # -x40000 to x3ffff
        #      ::= x59 b3 b2 b1 b0   # 32-bit integer cast to long
        if -0x10 <= v <= 0x2f:
            # 1-byte compact int (-0x10 to 0x2f)
            self._bytes.append(0x90 + v)
        elif -0x800 <= v <= 0x7ff:
            # 2-byte compact int (-0x800 to 0x7ff)
            self._bytes.append(0xc8 + (v >> 8))
            self._bytes.append(v & 0xff)
        elif -0x40000 <= v <= 0x3ffff:
            # 3-byte compact int (-0x40000 to 0x3ffff)
            self._bytes.append(0xd4 + (v >> 16))
            self._bytes.append((v >> 8) & 0xff)
            self._bytes.append(v & 0xff)
        elif -0x80000000 <= v <= 0x7fffffff:
            # 32-bit int (I)
            self._bytes.extend(pack('>cl', b'I', v))  # 'I'
        else:
            # 64-bit long (L)
            self._bytes.extend(pack('>cq', b'L', v))  # 'L'

    def write_float(self, v: float, force_double: bool = False) -> None:
        # double ::= 'D' b7 b6 b5 b4 b3 b2 b1 b0
        #        ::= x5b                   # 0.0
        #        ::= x5c                   # 1.0
        #        ::= x5d b0                # byte cast to double (-128.0 to 127.0)
        #        ::= x5e b1 b0             # short cast to double
        #        ::= x5f b3 b2 b1 b0       # 32-bit float cast to double
        if v == 0.0:
            self._bytes.append(0x5b)  # 0.0
        elif v == 1.0:
            self._bytes.append(0x5c)  # 1.0
        elif -128.0 <= v <= 127.0 and v.is_integer():
            # byte-sized double
            self._bytes.extend(pack('>cb', b'\x5d', int(v)))
        elif -32768.0 <= v <= 32767.0 and v.is_integer():
            # short-sized double
            self._bytes.extend(pack('>ch', b'\x5e', int(v)))
        elif (v * 1000).is_integer():
            # 小数部分不超过 3 位的
            # 此处对 0x5f 的解释和官网协议不一致，和 java 库保持一致
            self._bytes.extend(pack('>cl', b'\x5f', int(v * 1000)))
        else:
            # full 64-bit double ('D')
            self._bytes.extend(pack('>cd', b'D', v))

    def write_string(self, v: str) -> None:
        # string ::= 'R' b1 b0 <utf8-data>  # non-final chunk
        #        ::= 'S' b1 b0 <utf8-data>  # string of length 0-65535
        #        ::= [x00-x1f] <utf8-data>  # string of length 0-31
        #        ::= [x30-x34] <utf8-data>  # string of length 0-1023
        if v is None:
            self.write_null()
            return
        if not v:
            self._bytes.append(0x00)
            return

        l = len(v)  # 按字符计算，而不是按字节

        if l <= 32:
            # utf-8 string length 0-32
            self._bytes.append(0x00 + l)
            self._bytes.extend(v.encode())
        elif l <= 1023:
            # utf-8 string length 0-1023
            self._bytes.append(0x30 + (l >> 8))
            self._bytes.append(l & 0xff)
            self._bytes.extend(v.encode())
        else:
            # utf-8 string split into 64K chunks
            chunks = [v[i:i + 0x8000] for i in range(0, l, 0x8000)]
            for idx, chunk in enumerate(chunks):
                is_last_chunk = idx == len(chunks) - 1
                self._bytes.extend(pack('>cH', b'S' if is_last_chunk else b'R', len(chunk)))  # 'R' for non-final chunk, 'S' for final chunk
                self._bytes.extend(chunk.encode())

    def write_bytes(self, v: bytes) -> None:
        # binary ::= 'A; b1 b0 <binary-data>  # non-final chunk
        #        ::= 'B' b1 b0 <binary-data>  # final chunk
        #        ::= [x20-x2f] <binary-data>  # binary data of length 0-15
        #        ::= [x34-x37] <binary-data>  # binary data of length 0-1023
        if v is None:
            self.write_null()
            return
        if not v:
            self._bytes.append(0x20)
            return

        # 将字节数组按 4093 拆分为 chunks，至于为什么是 4093 是为了和 java 实现保持一致
        chunks = [v[i:i + 4093] for i in range(0, len(v), 4093)]
        for idx, chunk in enumerate(chunks):
            is_last_chunk = idx == len(chunks) - 1

            l = len(chunk)
            if l <= 15:
                # binary length 0-16
                self._bytes.append(0x20 + l)
                self._bytes.extend(chunk)
            elif l <= 1023:
                # binary length 0-1023
                self._bytes.append(0x34 + (l >> 8))
                self._bytes.append(l & 0xff)
                self._bytes.extend(chunk)
            else:
                # chunk
                self._bytes.extend(pack('>cH', b'B' if is_last_chunk else b'A', l))  # 'A' for non-final chunk, 'B' for final chunk
                self._bytes.extend(chunk)

    def write_datetime(self, v: datetime) -> None:
        # date ::= x4a b7 b6 b5 b4 b3 b2 b1 b0
        #      ::= x4b b3 b2 b1 b0       # minutes since epoch
        # only support 64-bit timestamp
        ts = int(v.timestamp() * 1000)
        self._bytes.extend(pack('>cq', b'J', ts))

    def write_list(self, v: list) -> None:
        # list ::= x55 type value* 'Z'   # variable-length list
        #      ::= 'V' type int value*   # fixed-length list
        #      ::= x57 value* 'Z'        # variable-length untyped list
        #      ::= x58 int value*        # fixed-length untyped list
        #      ::= [x70-77] type value*  # fixed-length typed list
        #      ::= [x78-7f] value*       # fixed-length untyped list
        # only encode as fixed-length untyped list
        # TODO
        l = len(v)
        if l <= 15:
            self._bytes.append(0x78 + l)
        else:
            self._bytes.append(0x58)
            self.write_int(l)
        for e in v:
            self.write(e)

    def write_map(self, v: dict) -> None:
        # map ::= 'M' type (value value)* 'Z'  # key, value map pairs
        # 	  ::= 'H' (value value)* 'Z'       # untyped key, value
        if v is None:
            self.write_null()
            return
        if self._try_write_ref(v):
            return

        cls_name = v.pop('#class', None)
        if cls_name:
            # 如果指定了 #class 则使用 M 协议，表示是一个 object
            self._bytes.append(0x4d)
            self._write_type(str(cls_name))
        else:
            # 如果未指定 #class 则使用 H 协议，对应 java.util.HashMap
            self._bytes.append(0x48)

        for k, v in v.items():
            self.write(k)
            self.write(v)
        self._bytes.append(0x5a)

    def write_object(self, v: dict) -> None:
        # object ::= 'O' int value*
        # 	     ::= [x60-x6f] value*
        # TODO
        raise NotImplementedError

    def _write_type(self, type_name: str) -> None:
        # type ::= string
        #      ::= int
        type_id = self._type_names.get(type_name, -1)
        if type_id == -1:
            self._type_names[type_name] = len(self._type_names)
            self.write_string(type_name)
        else:
            self.write_int(type_id)

    def _try_write_ref(self, o: Any) -> bool:
        # ref ::= x51 int  # reference to nth map/list/object
        idx = self._refs.get(id(o), -1)
        if idx == -1:
            self._refs[id(o)] = len(self._refs)
            return False
        else:
            self._bytes.append(0x51)
            self.write_int(idx)
            return True


class Hessian2Deserializer:

    def __init__(self, data: bytes, **kwargs):
        self._reader = _ByteReader(data)
        self._refs: List[Any] = []
        self._class_definitions: List[dict] = []
        self._type_names: List[str] = []

    def read(self, **kwargs) -> Any:
        b = self._reader.look_byte()
        if b == 0x4e:  # 'N'
            # null ::= 'N'
            return self.read_null()
        elif b == 0x54 or b == 0x46:  # 'T'
            # boolean ::= 'T'
            #         ::= 'F'
            return self.read_boolean()
        elif b == 0x49 or 0x80 <= b <= 0xbf or 0xc0 <= b <= 0xcf or 0xd0 <= b <= 0xd7:
            # int ::= 'I' b3 b2 b1 b0
            #     ::= [x80-xbf]          # -x10 to x3f
            #     ::= [xc0-xcf] b0       # -x800 to x7ff
            #     ::= [xd0-xd7] b1 b0    # -x40000 to x3ffff
            return self.read_int()
        elif b == 0x4c or 0xd8 <= b <= 0xef or 0xf0 <= b <= 0xff or 0x38 <= b <= 0x3f or b == 0x59:
            # long ::= 'L' b7 b6 b5 b4 b3 b2 b1 b0
            #      ::= [xd8-xef]         # -x08 to x0f
            #      ::= [xf0-xff] b0      # -x800 to x7ff
            #      ::= [x38-x3f] b1 b0   # -x40000 to x3ffff
            #      ::= x59 b3 b2 b1 b0   # 32-bit integer cast to long
            return self.read_int()
        elif b == 0x44 or b == 0x5b or b == 0x5c or b == 0x5d or b == 0x5e or b == 0x5f:
            # double ::= 'D' b7 b6 b5 b4 b3 b2 b1 b0
            #        ::= x5b                   # 0.0
            #        ::= x5c                   # 1.0
            #        ::= x5d b0                # byte cast to double (-128.0 to 127.0)
            #        ::= x5e b1 b0             # short cast to double
            #        ::= x5f b3 b2 b1 b0       # 32-bit float cast to double
            return self.read_float()
        elif b == 0x52 or b == 0x53 or 0x00 <= b <= 0x1f or 0x30 <= b <= 0x33:
            # string ::= 'R' b1 b0 <utf8-data>  # non-final chunk
            #        ::= 'S' b1 b0 <utf8-data>  # string of length 0-65535
            #        ::= [x00-x1f] <utf8-data>  # string of length 0-31
            #        ::= [x30-x33] <utf8-data>  # string of length 0-1023 协议原文写的是 x30-x34，但实际上 x34 表示的是 binary 不是 string
            return self.read_string()
        elif b == 0x41 or b == 0x42 or 0x20 <= b <= 0x2f or 0x34 <= b <= 0x37:
            # binary ::= 'A; b1 b0 <binary-data>  # non-final chunk
            #        ::= 'B' b1 b0 <binary-data>  # final chunk
            #        ::= [x20-x2f] <binary-data>  # binary data of length 0-15
            #        ::= [x34-x37] <binary-data>  # binary data of length 0-1023
            return self.read_bytes()
        elif b == 0x4a or b == 0x4b:
            # date ::= x4a b7 b6 b5 b4 b3 b2 b1 b0
            #      ::= x4b b3 b2 b1 b0       # minutes since epoch
            return self.read_datetime()
        elif b == 0x4d or b == 0x48:
            # map ::= 'M' type (value value)* 'Z'  # key, value map pairs
            #     ::= 'H' (value value)* 'Z'       # untyped key, value
            return self.read_map()
        elif b == 0x55 or b == 0x57 or 0x70 <= b <= 0x77 or 0x78 <= b <= 0x7f:
            # list ::= x55 type value* 'Z'   # variable-length list
            #      ::= 'V' type int value*   # fixed-length list
            #      ::= x57 value* 'Z'        # variable-length untyped list
            #      ::= x58 int value*        # fixed-length untyped list
            #      ::= [x70-77] type value*  # fixed-length typed list
            #      ::= [x78-7f] value*       # fixed-length untyped list
            return self.read_list()
        elif b == 0x4f or 0x60 <= b <= 0x6f:
            # object ::= 'O' int value*
            #        ::= [x60-x6f] value*
            return self.read_object()
        elif b == 0x51:
            # ref ::= x51 int  # reference to nth map/list/object
            return self.read_ref()
        elif b == 0x43:
            # class_def ::= 'C' string int string*
            return self.read_class_def()
        else:
            raise ValueError(f'token error {b}')

    def read_null(self) -> None:
        # null ::= 'N'
        self._reader.skip()

    def read_boolean(self) -> bool:
        # boolean ::= 'T'
        #         ::= 'F'
        return self._reader.next_byte() == 0x54

    def read_int(self) -> int:
        # int ::= 'I' b3 b2 b1 b0
        #     ::= [x80-xbf]          # -x10 to x3f
        #     ::= [xc0-xcf] b0       # -x800 to x7ff
        #     ::= [xd0-xd7] b1 b0    # -x40000 to x3ffff
        # long ::= 'L' b7 b6 b5 b4 b3 b2 b1 b0
        #      ::= [xd8-xef]         # -x08 to x0f
        #      ::= [xf0-xff] b0      # -x800 to x7ff
        #      ::= [x38-x3f] b1 b0   # -x40000 to x3ffff
        #      ::= x59 b3 b2 b1 b0   # 32-bit integer cast to long
        b = self._reader.next_byte()
        if b == 0x49:
            v, = unpack('>l', self._reader.next_bytes(4))
            return v
        if 0x80 <= b <= 0xbf:
            return b - 0x90
        if 0xc0 <= b <= 0xcf:
            return (b - 0xc8) << 8 | self._reader.next_byte()
        if 0xd0 <= b <= 0xd7:
            return (b - 0xd4) << 16 | self._reader.next_byte() << 8 | self._reader.next_byte()
        if b == 0x4c:
            v, = unpack('>q', self._reader.next_bytes(8))
            return v
        if 0xd8 <= b <= 0xef:
            return b - 0xd8
        if 0xf0 <= b <= 0xff:
            return (b - 0xf8) << 8 | self._reader.next_byte()
        if 0x38 <= b <= 0x3f:
            return (b - 0x38) << 16 | self._reader.next_byte() << 8 | self._reader.next_byte()
        if b == 0x59:
            v, = unpack('>l', self._reader.next_bytes(4))
            return v
        raise ValueError(f'token error {b} at {self._reader.pos()}')

    def read_float(self) -> float:
        # double ::= 'D' b7 b6 b5 b4 b3 b2 b1 b0
        #        ::= x5b                   # 0.0
        #        ::= x5c                   # 1.0
        #        ::= x5d b0                # byte cast to double (-128.0 to 127.0)
        #        ::= x5e b1 b0             # short cast to double
        #        ::= x5f b3 b2 b1 b0       # 32-bit float cast to double
        b = self._reader.next_byte()
        if b == 0x44:
            v, = unpack('>d', self._reader.next_bytes(8))
            return v
        if b == 0x5b:
            return 0.0
        if b == 0x5c:
            return 1.0
        if b == 0x5d:
            v, = unpack('>b', self._reader.next_bytes(1))
            return float(v)
        if b == 0x5e:
            v, = unpack('>h', self._reader.next_bytes(2))
            return float(v)
        if b == 0x5f:
            v, = unpack('>l', self._reader.next_bytes(4))
            return float(v / 1000)
        raise ValueError(f'token error {b} at {self._reader.pos()}')

    def read_string(self) -> str:
        # string ::= 'R' b1 b0 <utf8-data>  # non-final chunk
        #        ::= 'S' b1 b0 <utf8-data>  # string of length 0-65535
        #        ::= [x00-x1f] <utf8-data>  # string of length 0-31
        #        ::= [x30-x34] <utf8-data>  # string of length 0-1023
        buf = bytearray()
        b = self._reader.next_byte()
        if b == 0x52:  # read non-final chunk until final chunk
            while b == 0x52:
                l, = unpack('>H', self._reader.next_bytes(2))
                buf.extend(self._read_utf8_bytes(l))
                b = self._reader.next_byte()
        if b == 0x53:
            l, = unpack('>H', self._reader.next_bytes(2))
            buf.extend(self._read_utf8_bytes(l))
            return buf.decode()
        if 0x00 <= b <= 0x1f:
            l = b - 0x00
            buf.extend(self._read_utf8_bytes(l))
            return buf.decode()
        if 0x30 <= b <= 0x34:
            l = ((b - 0x30) << 8) + self._reader.next_byte()
            buf.extend(self._read_utf8_bytes(l))
            return buf.decode()
        raise ValueError(f'token error {b} at {self._reader.pos()}')

    def _read_utf8_bytes(self, n_chars: int) -> bytes:
        count = 0
        pos = self._reader.pos()
        start_pos = self._reader.pos()
        raw_data = self._reader.raw_data_unsafe()
        while count < n_chars:
            count += 1

            b = raw_data[pos]
            if b < 0x80:
                pos += 1
            elif b < 0xe0:
                pos += 2
            elif b < 0xf0:
                pos += 3
            else:
                pos += 4

        return self._reader.next_bytes(pos - start_pos)

    def read_bytes(self) -> bytes:
        # binary ::= 'A; b1 b0 <binary-data>  # non-final chunk
        #        ::= 'B' b1 b0 <binary-data>  # final chunk
        #        ::= [x20-x2f] <binary-data>  # binary data of length 0-15
        #        ::= [x34-x37] <binary-data>  # binary data of length 0-102
        buf = bytearray()
        b = self._reader.next_byte()
        if b == 0x41:  # read non-final chunk until final chunk
            while b == 0x41:
                l, = unpack('>h', self._reader.next_bytes(2))
                buf.extend(self._reader.next_bytes(l))
                b = self._reader.next_byte()
        if b == 0x42:
            l, = unpack('>h', self._reader.next_bytes(2))
            buf.extend(self._reader.next_bytes(l))
            return bytes(buf)
        if 0x20 <= b <= 0x2f:
            l = b - 0x20
            buf.extend(self._reader.next_bytes(l))
            return bytes(buf)
        if 0x34 <= b <= 0x37:
            l = ((b - 0x34) << 8) + self._reader.next_byte()
            buf.extend(self._reader.next_bytes(l))
            return bytes(buf)
        raise ValueError(f'token error {b} at {self._reader.pos()}')

    def read_datetime(self) -> datetime:
        # date ::= x4a b7 b6 b5 b4 b3 b2 b1 b0
        #      ::= x4b b3 b2 b1 b0       # minutes since epoch
        b = self._reader.next_byte()
        if b == 0x4a:
            v, = unpack('>q', self._reader.next_bytes(8))
            return datetime.fromtimestamp(v / 1000)
        if b == 0x4b:
            v, = unpack('>l', self._reader.next_bytes(4))
            return datetime.fromtimestamp(v * 60)
        raise ValueError(f'token error {b} at {self._reader.pos()}')

    def read_list(self) -> list:
        # list ::= x55 type value* 'Z'   # variable-length list
        #      ::= 'V' type int value*   # fixed-length list
        #      ::= x57 value* 'Z'        # variable-length untyped list
        #      ::= x58 int value*        # fixed-length untyped list
        #      ::= [x70-77] type value*  # fixed-length typed list
        #      ::= [x78-7f] value*       # fixed-length untyped list
        # TODO
        pass

    def read_map(self) -> dict:
        # map ::= 'M' type (value value)* 'Z'  # key, value map pairs
        # 	  ::= 'H' (value value)* 'Z'       # untyped key, value
        v = {}
        self._refs.append(v)
        b = self._reader.next_byte()
        if b == 0x4d:
            v['#class'] = self.read_type()
        elif b != 0x48:
            raise ValueError(f'token error {b} at {self._reader.pos()}')

        b = self._reader.look_byte()
        while b != 0x5a:
            k = self.read()
            v[k] = self.read()
            b = self._reader.look_byte()
        self._reader.skip()

        return v

    def read_object(self) -> dict:
        # object ::= 'O' int value*
        #        ::= [x60-x6f] value*
        # TODO
        pass

    def read_type(self) -> str:
        # type ::= string
        #      ::= int
        t = self.read()
        if isinstance(t, str):
            self._type_names.append(t)
            return t
        if isinstance(t, int):
            return self._type_names[t]
        raise AssertionError(f'read type error {type(t)} at {self._reader.pos()}')

    def read_ref(self) -> Any:
        # ref ::= x51 int  # reference to nth map/list/object
        self._reader.skip()
        idx = self.read_int()
        return self._refs[idx]

    def read_class_def(self) -> dict:
        # class_def ::= 'C' string int string*
        pass


class _ByteReader:
    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def look_byte(self) -> int:
        return self._data[self._pos]

    def next_byte(self) -> int:
        v = self._data[self._pos]
        self._pos += 1
        return v

    def next_bytes(self, length: int) -> bytes:
        v = self._data[self._pos:self._pos + length]
        self._pos += length
        return v

    def skip(self, length: int = 1) -> None:
        self._pos += length

    def pos(self) -> int:
        return self._pos

    def raw_data_unsafe(self) -> bytes:
        return self._data


def helloworld():
    return bytes(py3_hessian2_rsimpl.helloworld())
