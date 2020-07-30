from __future__ import annotations
from dataclasses import dataclass
from struct import pack as struct_pack, unpack_from as struct_unpack_from
from typing import ClassVar, ByteString


@dataclass
class Version:
    _RESERVED: ClassVar[bytes] = bytes(3)
    _NTLMRevisionCurrent: ClassVar[int] = 0x0F

    major_version_number: int = 0
    minor_version_number: int = 0
    build_number: int = 0

    @classmethod
    def from_bytes(cls, buffer: ByteString, base_offset: int = 0, strict: bool = True) -> Version:
        buffer = memoryview(buffer)[base_offset:]

        if strict:
            if (reserved := bytes(buffer[4:7])) != cls._RESERVED:
                # TODO: Use proper exception
                raise ValueError

            if (ntlm_revision_current := buffer[7]) != cls._NTLMRevisionCurrent:
                # TODO: Use proper exception
                raise ValueError

        return cls(
            major_version_number=buffer[0],
            minor_version_number=buffer[1],
            build_number=struct_unpack_from('<H', buffer=buffer, offset=2)[0]
        )

    def __bytes__(self):
        return b''.join([
            struct_pack('<B', self.major_version_number),
            struct_pack('<B', self.minor_version_number),
            struct_pack('<H', self.build_number),
            self._RESERVED,
            struct_pack('<B', self._NTLMRevisionCurrent)
        ])

