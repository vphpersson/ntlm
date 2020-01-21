from __future__ import annotations
from enum import IntEnum, IntFlag
from struct import pack as struct_pack, unpack as struct_unpack
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import List, ClassVar, Any

from msdsalgs.time import filetime_to_datetime
from msdsalgs.utils import Mask

from ntlm.structures.single_host_data import SingleHostData
from ntlm.internal_utils import get_message_bytes_data


class MalformedAvPairSequenceError(Exception):
    def __init__(self, msg: str = 'The AV pair sequence is malformed.'):
        super().__init__(msg)


class EOLNotLastError(MalformedAvPairSequenceError):
    def __init__(self):
        super().__init__('There is at least one additional AVPair after an observed EOL entry.')


class EOLNotObservedError(MalformedAvPairSequenceError):
    def __init__(self):
        super().__init__('No EOL was observed.')


class AvFlagsMask(IntFlag):
    ACCOUNT_AUTHENTICATION_CONSTRAINED = 0x00000001
    USE_MIC = 0x00000002
    SPN_UNTRUSTED_SOURCE = 0x00000004


AvFlags = Mask.make_class(AvFlagsMask)


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

    def _to_bytes_base(self, value_bytes: bytes) -> bytes:
        return struct_pack('<HH', self.AV_ID, len(value_bytes)) + value_bytes

    @abstractmethod
    def __bytes__(self) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def get_value(self) -> Any:
        raise NotImplementedError

    # TODO: Make nice.
    @classmethod
    def from_id(cls, av_id: AvId, value: bytes) -> 'AVPair':

        if av_id == AvId.MsvAvNbComputerName:
            return ComputerNameAVPair(computer_name=value.decode(encoding='utf-16-le'))
        elif av_id == AvId.MsvAvNbDomainName:
            return DomainNameAVPair(domain_name=value.decode(encoding='utf-16-le'))
        elif av_id == AvId.MsvAvDnsComputerName:
            return DnsComputerNameAVPair(dns_comptuer_name=value.decode(encoding='utf-16-le'))
        elif av_id == AvId.MsvAvDnsDomainName:
            return DnsDomainNameAVPair(dns_domain_name=value.decode(encoding='utf-16-le'))
        elif av_id == AvId.MsvAvDnsTreeName:
            return DnsTreeNameAVPair(dns_tree_name=value.decode(encoding='utf-16-le'))
        elif av_id == AvId.MsvAvTimestamp:
            return TimestampAVPair(
                filetime=value,
                timestamp=filetime_to_datetime(filetime=struct_unpack('<Q', value)[0])
            )
        elif av_id == AvId.MsvAvFlags:
            return FlagsAVPair(flags=AvFlags.from_int(AvFlagsMask(struct_unpack('<I', value)[0])))
        elif av_id == AvId.MsvAvTargetName:
            return TargetNameAVPair(target_name=value.decode(encoding='utf-16-le'))
        elif av_id == AvId.MsvChannelBindings:
            return ChannelBindingsAVPair(channel_bindings=value)
        elif av_id == AvId.MsvAvSingleHost:
            return SingleHostDataAVPair(single_host_data=SingleHostData.from_bytes(data=value))
        elif av_id == AvId.MsvAvEOL:
            return EOLAVPair()
        else:
            # TODO: Use proper exception.
            raise ValueError


@dataclass
class ComputerNameAVPair(AVPair):
    AV_ID = AvId.MsvAvNbComputerName
    computer_name: str

    def get_value(self) -> str:
        return self.computer_name

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=self.computer_name.encode(encoding='utf-16-le'))


@dataclass
class DomainNameAVPair(AVPair):
    AV_ID = AvId.MsvAvNbDomainName
    domain_name: str

    def get_value(self) -> str:
        return self.domain_name

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=self.domain_name.encode(encoding='utf-16-le'))


@dataclass
class DnsComputerNameAVPair(AVPair):
    AV_ID = AvId.MsvAvDnsComputerName
    dns_comptuer_name: str

    def get_value(self) -> str:
        return self.dns_comptuer_name

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=self.dns_comptuer_name.encode(encoding='utf-16-le'))


@dataclass
class DnsDomainNameAVPair(AVPair):
    AV_ID = AvId.MsvAvDnsDomainName
    dns_domain_name: str

    def get_value(self) -> str:
        return self.dns_domain_name

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=self.dns_domain_name.encode(encoding='utf-16-le'))


@dataclass
class DnsTreeNameAVPair(AVPair):
    AV_ID = AvId.MsvAvDnsTreeName
    dns_tree_name: str

    def get_value(self) -> str:
        return self.dns_tree_name

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=self.dns_tree_name.encode(encoding='utf-16-le'))


@dataclass
class TimestampAVPair(AVPair):
    AV_ID = AvId.MsvAvTimestamp
    # NOTE: When converting a `FILETIME` to a `datetime` there is a loss of precision. To have deserialization return
    # the same value as was input, we stored the input original, input `FILETIME` value.
    filetime: bytes
    timestamp: datetime

    def get_value(self) -> datetime:
        return self.timestamp

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=self.filetime)


@dataclass
class FlagsAVPair(AVPair):
    AV_ID = AvId.MsvAvFlags
    flags: AvFlags

    def get_value(self) -> AvFlags:
        return self.flags

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=struct_pack('<I', int(self.flags)))


@dataclass
class TargetNameAVPair(AVPair):
    AV_ID = AvId.MsvAvTargetName
    target_name: str

    def get_value(self) -> str:
        return self.target_name

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=self.target_name.encode(encoding='utf-16-le'))


@dataclass
class ChannelBindingsAVPair(AVPair):
    AV_ID = AvId.MsvChannelBindings
    channel_bindings: bytes

    def get_value(self) -> bytes:
        return self.channel_bindings

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=self.channel_bindings)


@dataclass
class SingleHostDataAVPair(AVPair):
    AV_ID = AvId.MsvAvSingleHost
    single_host_data: SingleHostData

    def get_value(self) -> SingleHostData:
        return self.single_host_data

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=bytes(self.single_host_data))


@dataclass
class EOLAVPair(AVPair):
    AV_ID = AvId.MsvAvEOL

    def get_value(self) -> None:
        return None

    def __bytes__(self) -> bytes:
        return self._to_bytes_base(value_bytes=b'')


class AVPairSequence(list):
    """
    A list of `AVPair`s.
    """

    def __init__(self, iterable=()):
        super().__init__(iterable)

    def add_av_pair(self, av_pair: AVPair) -> None:
        if isinstance(av_pair, EOLAVPair):
            if len(self) == 0 or not isinstance(self[-1], EOLAVPair):
                self.append(av_pair)
        else:
            eol_av_pair = EOLAVPair() if len(self) == 0 else self.pop()
            self.extend([av_pair, eol_av_pair])

    @classmethod
    def from_bytes(cls, data: bytes) -> 'AVPairSequence':
        offset = 0
        av_pairs_list: List[AVPair] = []

        while offset + 4 <= len(data):
            av_id, av_len = struct_unpack('<HH', data[offset:offset + 4])
            av_pairs_list.append(
                AVPair.from_id(
                    av_id=av_id,
                    value=get_message_bytes_data(
                        bytes_data=data,
                        length=av_len,
                        alloc=0,
                        offset=offset + 4
                    )
                )
            )

            offset += 4 + av_len

        return cls(av_pairs_list)

    def __bytes__(self) -> bytes:
        return b''.join(bytes(av_pair) for av_pair in self.__iter__())
