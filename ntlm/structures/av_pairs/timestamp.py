from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from datetime import datetime

from msdsalgs.time import filetime_to_datetime

from ntlm.structures.av_pairs import AVPair, AvId


@AVPair.register
@dataclass
class TimestampAVPair(AVPair):
    AV_ID: ClassVar[AvId] = AvId.MsvAvTimestamp
    LABEL: ClassVar[str] = 'Server time'

    # NOTE: When converting a `FILETIME` to a `datetime` there is a loss of precision. To have deserialization return
    # the same value as was input, we stored the input original, input `FILETIME` value.
    filetime: bytes
    timestamp: datetime

    def get_value(self) -> datetime:
        return self.timestamp

    @classmethod
    def from_value_bytes(cls, value_bytes: bytes) -> TimestampAVPair:
        return cls(
            filetime=value_bytes,
            timestamp=filetime_to_datetime(filetime=struct_unpack_from('<Q', buffer=value_bytes)[0])
        )

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=self.filetime)