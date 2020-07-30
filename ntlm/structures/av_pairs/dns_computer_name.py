from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar

from ntlm.structures.av_pairs import AVPair, AvId


@AVPair.register
@dataclass
class DnsComputerNameAVPair(AVPair):
    AV_ID: ClassVar[AvId] = AvId.MsvAvDnsComputerName
    LABEL: ClassVar[str] = 'Server FQDN'

    dns_comptuer_name: str

    def get_value(self) -> str:
        return self.dns_comptuer_name

    @classmethod
    def from_value_bytes(cls, value_bytes: bytes) -> DnsComputerNameAVPair:
        return cls(dns_comptuer_name=value_bytes.decode(encoding='utf-16-le'))

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=self.dns_comptuer_name.encode(encoding='utf-16-le'))