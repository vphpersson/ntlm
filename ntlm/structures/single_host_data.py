from dataclasses import dataclass
from struct import unpack as struct_unpack, pack as struct_pack

# TODO: Add `ClassVar`s.


@dataclass
class SingleHostData:
    _size: int
    custom_data: bytes
    machine_id: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> 'SingleHostData':
        z4: bytes = data[4:8]
        if z4 != b'\x00\x00\x00\x00':
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
            4 * b'\x00',
            self.custom_data,
            self.machine_id
        ])

    def __len__(self) -> int:
        return 48
