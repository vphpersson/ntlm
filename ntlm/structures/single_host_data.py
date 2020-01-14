from __future__ import annotations
from dataclasses import dataclass
from struct import unpack as struct_unpack, pack as struct_pack
from typing import ClassVar

# TODO: Add `ClassVar`s.


@dataclass
class SingleHostData:
    _Z4: ClassVar[bytes] = bytes(4)

    _size: int
    custom_data: bytes
    machine_id: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> SingleHostData:
        if data[4:8] != cls._Z4:
            # TODO: Use proper exception.
            raise ValueError

        return cls(
            _size=struct_unpack('<I', data[:4])[0],
            custom_data=data[8:16],
            machine_id=data[16:48]
        )

    def __bytes__(self) -> bytes:
        return b''.join([
            struct_pack('<I', self._size),
            self._Z4,
            self.custom_data,
            self.machine_id
        ])

    def __len__(self) -> int:
        return 48
