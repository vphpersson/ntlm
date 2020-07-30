from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar

from ntlm.structures.av_pairs import AVPair, AvId


@AVPair.register
@dataclass
class ChannelBindingsAVPair(AVPair):
    AV_ID: ClassVar[AvId] = AvId.MsvChannelBindings
    LABEL: ClassVar[str] = 'Channel binding hash'

    channel_bindings: bytes

    def get_value(self) -> bytes:
        return self.channel_bindings

    @classmethod
    def from_value_bytes(cls, value_bytes: bytes) -> ChannelBindingsAVPair:
        return cls(channel_bindings=value_bytes)

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=self.channel_bindings)