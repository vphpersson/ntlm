from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar

from ntlm.structures.av_pairs import AVPair, AvId


@AVPair.register
@dataclass
class DnsTreeNameAVPair(AVPair):
    AV_ID: ClassVar[AvId] = AvId.MsvAvDnsTreeName
    LABEL: ClassVar[str] = 'Forest FQDN'

    dns_tree_name: str

    def get_value(self) -> str:
        return self.dns_tree_name

    @classmethod
    def from_value_bytes(cls, value_bytes: bytes) -> DnsTreeNameAVPair:
        return cls(dns_tree_name=value_bytes.decode(encoding='utf-16-le'))

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=self.dns_tree_name.encode(encoding='utf-16-le'))