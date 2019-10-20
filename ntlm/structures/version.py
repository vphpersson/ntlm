from dataclasses import dataclass
from struct import pack as struct_pack


@dataclass
class Version:
    major_version_number: int
    minor_version_number: int
    build_number: int

    def __bytes__(self):
        return b''.join([
            struct_pack('<B', self.major_version_number),
            struct_pack('<B', self.minor_version_number),
            struct_pack('<H', self.build_number),
            3 * b'\x00',
            b'\x0F'
        ])
