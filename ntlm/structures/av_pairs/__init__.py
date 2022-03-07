from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Type, Any, ByteString
from enum import IntEnum
from abc import ABC, abstractmethod
from struct import pack as struct_pack, unpack_from as struct_unpack_from

from ntlm._utils import get_message_bytes_data


class AvId(IntEnum):
    MsvAvEOL = 0x0000
    MsvAvNbComputerName = 0x0001
    MsvAvNbDomainName = 0x0002
    MsvAvDnsComputerName = 0x0003
    MsvAvDnsDomainName = 0x0004
    MsvAvDnsTreeName = 0x0005
    # TODO: This is a mask as well...
    MsvAvFlags = 0x0006
    MsvAvTimestamp = 0x0007
    MsvAvSingleHost = 0x0008
    MsvAvTargetName = 0x0009
    MsvChannelBindings = 0x000A


@dataclass
class AVPair(ABC):
    """
    [MS-NLMP]: AV_PAIR
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
    """

    AV_ID: ClassVar[AvId] = NotImplemented
    LABEL: ClassVar[str] = NotImplemented

    AV_ID_TO_AV_PAIR_CLASS: ClassVar[dict[AvId, Type[AVPair]]] = {}

    def _to_bytes_base(self, value_bytes: bytes) -> bytes:
        return struct_pack('<HH', self.AV_ID, len(value_bytes)) + value_bytes

    @abstractmethod
    def __bytes__(self) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def get_value(self) -> Any:
        raise NotImplementedError

    @classmethod
    def from_bytes(cls, buffer: ByteString, base_offset: int = 0) -> AVPair:

        from ntlm.structures.av_pairs.single_host_data import SingleHostDataAVPair
        from ntlm.structures.av_pairs.dns_tree_name import DnsTreeNameAVPair
        from ntlm.structures.av_pairs.channel_bindings import ChannelBindingsAVPair
        from ntlm.structures.av_pairs.target_name import TargetNameAVPair
        from ntlm.structures.av_pairs.dns_computer_name import DnsComputerNameAVPair
        from ntlm.structures.av_pairs.flags import FlagsAVPair
        from ntlm.structures.av_pairs.domain_name import DomainNameAVPair
        from ntlm.structures.av_pairs.timestamp import TimestampAVPair
        from ntlm.structures.av_pairs.computer_name import ComputerNameAVPair
        from ntlm.structures.av_pairs.eol import EOLAVPair
        from ntlm.structures.av_pairs.dns_domain_name import DnsDomainNameAVPair

        buffer = memoryview(buffer)[base_offset:]

        av_id, av_len = struct_unpack_from('<HH', buffer=buffer, offset=0)
        value_bytes: bytes = get_message_bytes_data(buffer=buffer, length=av_len, alloc=0, offset=4)

        if cls != AVPair:
            if av_id != cls.AV_ID:
                # TODO: Use proper exception.
                raise ValueError
            return cls.from_value_bytes(value_bytes=value_bytes)
        else:
            return cls.AV_ID_TO_AV_PAIR_CLASS[av_id].from_value_bytes(value_bytes=value_bytes)

    @classmethod
    def register(cls, av_pair_class: Type[AVPair]) -> Type[AVPair]:
        cls.AV_ID_TO_AV_PAIR_CLASS[av_pair_class.AV_ID] = av_pair_class
        return av_pair_class

    @classmethod
    @abstractmethod
    def from_value_bytes(cls, value_bytes: bytes) -> AVPair:
        raise NotImplementedError
