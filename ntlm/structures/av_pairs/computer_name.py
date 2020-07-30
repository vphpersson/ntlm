from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar

from ntlm.structures.av_pairs import AVPair, AvId


@AVPair.register
@dataclass
class ComputerNameAVPair(AVPair):
    AV_ID: ClassVar[AvId] = AvId.MsvAvNbComputerName
    LABEL: ClassVar[str] = 'Server NetBIOS computer name'

    computer_name: str

    def get_value(self) -> str:
        return self.computer_name

    @classmethod
    def from_value_bytes(cls, value_bytes: bytes) -> ComputerNameAVPair:
        return cls(computer_name=value_bytes.decode(encoding='utf-16-le'))

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=self.computer_name.encode(encoding='utf-16-le'))
