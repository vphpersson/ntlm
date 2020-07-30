from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar

from ntlm.structures.av_pairs import AVPair, AvId
from ntlm.structures.single_host_data import SingleHostData


@AVPair.register
@dataclass
class SingleHostDataAVPair(AVPair):
    AV_ID: ClassVar[AvId] = AvId.MsvAvSingleHost
    LABEL: ClassVar[str] = 'Single host data'

    single_host_data: SingleHostData

    def get_value(self) -> SingleHostData:
        return self.single_host_data

    @classmethod
    def from_value_bytes(cls, value_bytes: bytes) -> SingleHostDataAVPair:
        return cls(single_host_data=SingleHostData.from_bytes(data=value_bytes))

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=bytes(self.single_host_data))
