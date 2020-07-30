from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, ClassVar
from struct import pack as struct_pack, unpack_from as struct_unpack_from

from ntlm.messages import Message
from ntlm.structures.version import Version
from ntlm.structures.negotiate_flags import NegotiateFlags
from ntlm._utils import get_message_bytes_data_str
from ntlm.exceptions import MalformedNegotiateMessageError


@Message.register
@dataclass
class NegotiateMessage(Message):
    MESSAGE_TYPE_ID: ClassVar[int] = 1
    _MALFORMED_EXCEPTION_CLASS: ClassVar = MalformedNegotiateMessageError

    negotiate_flags: NegotiateFlags
    domain_name: str = ''
    workstation_name: str = ''
    os_version: Optional[Version] = None

    @classmethod
    def _from_bytes(cls, buffer: memoryview, strict: bool = True) -> NegotiateMessage:
        domain_name_offset: int = struct_unpack_from('<I', buffer=buffer, offset=20)[0]
        workstation_name_offset: int = struct_unpack_from('<I', buffer=buffer, offset=28)[0]

        payload_offset_start: int = min(domain_name_offset, workstation_name_offset)

        return cls(
            negotiate_flags=NegotiateFlags.from_int(
                value=struct_unpack_from('<I', buffer=buffer, offset=12)[0]
            ),
            domain_name=get_message_bytes_data_str(
                buffer,
                *struct_unpack_from('<HH', buffer[16:20]),
                domain_name_offset
            ),
            workstation_name=get_message_bytes_data_str(
                buffer,
                *struct_unpack_from('<HH', buffer[24:28]),
                workstation_name_offset
            ),
            os_version=Version.from_bytes(buffer=buffer[32:40]) if payload_offset_start != 32 else None
        )

    def __bytes__(self) -> bytes:

        current_payload_offset: int = 32

        version_bytes: bytes = bytes(self.os_version) if self.os_version is not None else b''
        current_payload_offset += len(version_bytes)

        domain_bytes: bytes = self.domain_name.encode(encoding='utf-16-le')
        domain_bytes_len: int = len(domain_bytes)
        domain_name_fields: bytes = struct_pack('<HHI', domain_bytes_len, domain_bytes_len, current_payload_offset)
        current_payload_offset += domain_bytes_len

        workstation_bytes: bytes = self.workstation_name.encode(encoding='utf-16-le')
        workstation_bytes_len: int = len(workstation_bytes)
        workstation_fields: bytes = struct_pack(
            '<HHI',
            workstation_bytes_len,
            workstation_bytes_len,
            current_payload_offset
        )
        current_payload_offset += workstation_bytes_len

        return b''.join([
            Message.SIGNATURE,
            struct_pack('<I', NegotiateMessage.MESSAGE_TYPE_ID),
            struct_pack('<I', int(self.negotiate_flags)),
            domain_name_fields,
            workstation_fields,
            version_bytes,
            domain_bytes,
            workstation_bytes
        ])
