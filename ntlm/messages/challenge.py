from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, ClassVar
from struct import pack as struct_pack, unpack_from as struct_unpack_from

from ntlm.messages import Message
from ntlm.structures.negotiate_flags import NegotiateFlags
from ntlm.structures.av_pair_sequence import AVPairSequence
from ntlm.structures.version import Version
from ntlm._utils import get_message_bytes_data_str, get_message_bytes_data
from ntlm.exceptions import MalformedMessageError, MalformedChallengeMessageError


@Message.register
@dataclass
class ChallengeMessage(Message):
    MESSAGE_TYPE_ID: ClassVar[int] = 2
    MALFORMED_MESSAGE_ERROR_CLASS: ClassVar[MalformedMessageError] = MalformedChallengeMessageError
    _RESERVED: ClassVar[bytes] = bytes(8)

    negotiate_flags: NegotiateFlags
    challenge: bytes
    target_name: str = ''
    target_info: Optional[AVPairSequence] = None
    os_version: Optional[Version] = None

    @classmethod
    def _from_bytes(cls, buffer: memoryview, strict: bool = True) -> ChallengeMessage:
        # TODO: Check reserved.

        target_name_offset: int = struct_unpack_from('<I', buffer=buffer, offset=16)[0]
        target_info_offset: int = struct_unpack_from('<I', buffer=buffer, offset=44)[0]

        payload_offset_start: int = min(target_name_offset, target_info_offset)

        target_info_bytes: bytes = get_message_bytes_data(
            buffer,
            *struct_unpack_from('<HH', buffer=buffer, offset=40),
            target_info_offset
        )

        return cls(
            target_name=get_message_bytes_data_str(
                buffer,
                *struct_unpack_from('<HH', buffer=buffer, offset=12),
                target_name_offset
            ),
            negotiate_flags=NegotiateFlags.from_int(value=struct_unpack_from('<I', buffer=buffer, offset=20)[0]),
            challenge=bytes(buffer[24:32]),
            target_info=AVPairSequence.from_bytes(
                buffer=target_info_bytes,
                break_on_eol=True
            ) if target_info_bytes else None,
            os_version=Version.from_bytes(buffer=buffer, base_offset=48) if payload_offset_start != 48 else None
        )

    def __bytes__(self) -> bytes:
        current_payload_offset = 48

        version_bytes: bytes = bytes(self.os_version) if self.negotiate_flags.negotiate_version else b''
        current_payload_offset += len(version_bytes)

        target_name_bytes = self.target_name.encode(encoding='utf-16-le')
        target_name_bytes_len = len(target_name_bytes)
        target_name_fields = struct_pack('<HHI', target_name_bytes_len, target_name_bytes_len, current_payload_offset)
        current_payload_offset += target_name_bytes_len

        target_info_bytes = bytes(self.target_info) if self.target_info else b''
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
