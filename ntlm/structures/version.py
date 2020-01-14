from dataclasses import dataclass
from struct import pack as struct_pack
from typing import ClassVar


@dataclass
class Version:
    _RESERVED: ClassVar[bytes] = bytes(3)
    _NTLMRevisionCurrent: ClassVar[bytes] = b'\x0F'

    major_version_number: int
    minor_version_number: int
    build_number: int

    def __bytes__(self):
        return b''.join([
            struct_pack('<B', self.major_version_number),
            struct_pack('<B', self.minor_version_number),
            struct_pack('<H', self.build_number),
            self._RESERVED,
            self._NTLMRevisionCurrent
        ])
