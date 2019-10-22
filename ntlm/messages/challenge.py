from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, ClassVar
from struct import unpack as struct_unpack, pack as struct_pack

from .base import NTLMMessage
from ..structures.negotiate_flags import NegotiateFlags
from ..structures.av_pair import AVPairSequence
from ..structures.version import Version
from ..internal_utils import get_message_bytes_data_str, get_message_bytes_data
from ..exceptions import MalformedChallengeMessageError


@dataclass
class ChallengeMessage(NTLMMessage):
    negotiate_flags: NegotiateFlags
    target_name: str
    challenge: bytes
    target_info: Optional[AVPairSequence] = None
    os_version: Optional[Version] = None

    message_type_id: ClassVar[int] = 2
    _reserved: ClassVar[bytes] = 8 * b'\x00'
    _malformed_exception_class: ClassVar = MalformedChallengeMessageError

    # TODO: Support `strict` mode?
    @classmethod
    def from_bytes(cls, message_bytes: bytes) -> ChallengeMessage:

        cls.check_signature(signature_data=struct_unpack('<8s', message_bytes[0:8])[0])
        cls.check_message_type(
            message_type_id=struct_unpack('<I', message_bytes[8:12])[0],
            message_bytes=message_bytes
        )

        flags = NegotiateFlags.from_mask(struct_unpack('<I', message_bytes[20:24])[0])

        return cls(
            target_name=get_message_bytes_data_str(
                message_bytes,
                *struct_unpack('<HHI', message_bytes[12:20])
            ) if flags.request_target else None,
            negotiate_flags=flags,
            challenge=message_bytes[24:32],
            target_info=AVPairSequence.from_bytes(
                data=get_message_bytes_data(
                    message_bytes,
                    *struct_unpack('<HHI', message_bytes[40:48])
                )
            ) if flags.negotiate_target_info else None,
            os_version=Version(*struct_unpack('<BBH', message_bytes[48:52])) if flags.negotiate_version else None
        )

    def __bytes__(self) -> bytes:
        current_payload_offset = 48

        version_bytes: bytes = bytes(self.os_version) if self.negotiate_flags.negotiate_version else b''
        current_payload_offset += len(version_bytes)

        target_name_bytes = str.encode(
            self.target_name if self.negotiate_flags.request_target else '', encoding='utf-16-le'
        )
        target_name_bytes_len = len(target_name_bytes)
        target_name_fields = struct_pack('<HHI', target_name_bytes_len, target_name_bytes_len, current_payload_offset)
        current_payload_offset += target_name_bytes_len

        target_info_bytes = bytes(self.target_info) if self.negotiate_flags.negotiate_target_info else b''
        target_info_len = len(target_info_bytes)
        target_info_fields = struct_pack('<HHI', target_info_len, target_info_len, current_payload_offset)
        current_payload_offset += target_info_len

        return b''.join([
            NTLMMessage.signature,
            struct_pack('<I', self.message_type_id),
            target_name_fields,
            struct_pack('<I', self.negotiate_flags.to_mask().value),
            self.challenge,
            self._reserved,
            target_info_fields,
            version_bytes,
            target_name_bytes,
            target_info_bytes
        ])

