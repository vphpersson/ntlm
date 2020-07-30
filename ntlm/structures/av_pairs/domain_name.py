from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar

from ntlm.structures.av_pairs import AVPair, AvId


@AVPair.register
@dataclass
class DomainNameAVPair(AVPair):
    AV_ID: ClassVar[AvId] = AvId.MsvAvNbDomainName
    LABEL: ClassVar[str] = 'Server NetBIOS domain name'

    domain_name: str

    def get_value(self) -> str:
        return self.domain_name

    @classmethod
    def from_value_bytes(cls, value_bytes: bytes) -> DomainNameAVPair:
        return cls(domain_name=value_bytes.decode(encoding='utf-16-le'))

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=self.domain_name.encode(encoding='utf-16-le'))