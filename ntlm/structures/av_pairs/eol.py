from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar

from ntlm.structures.av_pairs import AVPair, AvId


@AVPair.register
@dataclass
class EOLAVPair(AVPair):
    AV_ID: ClassVar[AvId] = AvId.MsvAvEOL

    def get_value(self) -> None:
        return None

    @classmethod
    def from_value_bytes(cls, value_bytes: bytes) -> EOLAVPair:
        return cls()

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=b'')
