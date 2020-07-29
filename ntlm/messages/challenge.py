from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, ClassVar
from struct import unpack as struct_unpack, pack as struct_pack

from ntlm.messages import Message, register_ntlm_message
from ntlm.structures.negotiate_flags import NegotiateFlags
from ntlm.structures.av_pair import AVPairSequence
from ntlm.structures.version import Version
from ntlm.internal_utils import get_message_bytes_data_str, get_message_bytes_data
from ntlm.exceptions import MalformedMessageError, MalformedChallengeMessageError


@register_ntlm_message
@dataclass
class ChallengeMessage(Message):
    MESSAGE_TYPE_ID: ClassVar[int] = 2
    MALFORMED_MESSAGE_ERROR_CLASS: ClassVar[MalformedMessageError] = MalformedChallengeMessageError
    _RESERVED: ClassVar[bytes] = bytes(8)

    negotiate_flags: NegotiateFlags
    target_name: str
    challenge: bytes
    target_info: Optional[AVPairSequence] = None
    os_version: Optional[Version] = None

    # TODO: Support `strict` mode?
    @classmethod
    def _from_bytes(cls, data: bytes) -> ChallengeMessage:
        flags = NegotiateFlags.from_int(struct_unpack('<I', data[20:24])[0])

        return cls(
            target_name=get_message_bytes_data_str(
                data,
                *struct_unpack('<HHI', data[12:20])
            ) if flags.request_target else None,
            negotiate_flags=flags,
            challenge=data[24:32],
            target_info=AVPairSequence.from_bytes(
                data=get_message_bytes_data(
                    data,
                    *struct_unpack('<HHI', data[40:48])
                )
            ) if flags.negotiate_target_info else None,
            os_version=Version(*struct_unpack('<BBH', data[48:52])) if flags.negotiate_version else None
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
            Message.SIGNATURE,
            struct_pack('<I', self.MESSAGE_TYPE_ID),
            target_name_fields,
            struct_pack('<I', int(self.negotiate_flags)),
            self.challenge,
            self._RESERVED,
            target_info_fields,
            version_bytes,
            target_name_bytes,
            target_info_bytes
        ])

