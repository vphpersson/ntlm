from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar

from ntlm.structures.av_pairs import AVPair, AvId


@AVPair.register
@dataclass
class TargetNameAVPair(AVPair):
    AV_ID: ClassVar[AvId] = AvId.MsvAvTargetName
    LABEL: ClassVar[str] = 'Server SPN'

    target_name: str

    def get_value(self) -> str:
        return self.target_name

    @classmethod
    def from_value_bytes(cls, value_bytes: bytes) -> TargetNameAVPair:
        return cls(target_name=value_bytes.decode(encoding='utf-16-le'))

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=self.target_name.encode(encoding='utf-16-le'))