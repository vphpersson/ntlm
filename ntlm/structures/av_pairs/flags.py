from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from struct import pack as struct_pack, unpack_from as struct_unpack_from
from enum import IntFlag

from msdsalgs.utils import Mask

from ntlm.structures.av_pairs import AVPair, AvId


# TODO: Not sure this is the right place to put this.
class AvFlagsMask(IntFlag):
    ACCOUNT_AUTHENTICATION_CONSTRAINED = 0x00000001
    USE_MIC = 0x00000002
    SPN_UNTRUSTED_SOURCE = 0x00000004


AvFlags = Mask.make_class(AvFlagsMask)


@AVPair.register
@dataclass
class FlagsAVPair(AVPair):
    AV_ID: ClassVar[AvId] = AvId.MsvAvFlags
    LABEL: ClassVar[str] = 'Configuration'

    flags: AvFlags

    def get_value(self) -> AvFlags:
        return self.flags

    @classmethod
    def from_value_bytes(cls, value_bytes: bytes) -> FlagsAVPair:
        return cls(flags=AvFlags.from_int(value=struct_unpack_from('<I', buffer=value_bytes)[0]))

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=struct_pack('<I', int(self.flags)))
