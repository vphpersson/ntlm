from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, ClassVar, Union, ByteString
from struct import pack as struct_pack, unpack_from as struct_unpack_from

from ntlm.messages import Message
from ntlm.structures.negotiate_flags import NegotiateFlags
from ntlm.structures.ntlmv2_response import NTLMv2Response
from ntlm.structures.version import Version
from ntlm._utils import get_message_bytes_data, get_message_bytes_data_str
from ntlm.exceptions import MalformedMessageError, MalformedAuthenticateMessageError


@Message.register
@dataclass
class AuthenticateMessage(Message):
    MESSAGE_TYPE_ID: ClassVar[int] = 3
    MALFORMED_MESSAGE_ERROR_CLASS: ClassVar[MalformedMessageError] = MalformedAuthenticateMessageError

    lm_challenge_response: bytes
    nt_challenge_response: NTLMv2Response
    domain_name: str
    user_name: str
    negotiate_flags: NegotiateFlags
    workstation_name: str = ''
    encrypted_random_session_key: bytes = b''
    os_version: Optional[Version] = Version()
    mic: Optional[bytes] = bytes(16)

    @classmethod
    def _from_bytes(cls, buffer: memoryview, strict: bool = True) -> AuthenticateMessage:
        return cls(
            lm_challenge_response=get_message_bytes_data(
                buffer,
                *struct_unpack_from('<HHI', buffer=buffer, offset=12),
            ),
            nt_challenge_response=NTLMv2Response.from_bytes(
                buffer=get_message_bytes_data(
                    buffer,
                    *struct_unpack_from('<HHI', buffer=buffer, offset=20),
                )
            ),
            domain_name=get_message_bytes_data_str(buffer, *struct_unpack_from('<HHI', buffer=buffer, offset=28)),
            user_name=get_message_bytes_data_str(buffer, *struct_unpack_from('<HHI', buffer=buffer, offset=36)),
            workstation_name=get_message_bytes_data_str(buffer, *struct_unpack_from('<HHI', buffer=buffer, offset=44)),
            encrypted_random_session_key=get_message_bytes_data(
                buffer,
                *struct_unpack_from('<HHI', buffer=buffer, offset=52)
            ),
            negotiate_flags=NegotiateFlags.from_int(value=struct_unpack_from('<I', buffer=buffer, offset=60)[0]),
            os_version=Version.from_bytes(buffer=buffer, base_offset=64),
            mic=bytes(buffer[72:88])
        )

    def __bytes__(self) -> bytes:
        version_bytes: bytes = bytes(self.os_version) if self.os_version is not None else bytes(8)
        mic_bytes: bytes = self.mic if self.mic is not None else bytes(16)

        # TODO: It may be the case that the MIC and Version can be omitted, saving some bytes. Support that in future.

        current_payload_offset = 88

        lm_challenge_response_bytes_len = len(self.lm_challenge_response)
        lm_challenge_response_fields = struct_pack(
            '<HHI',
            lm_challenge_response_bytes_len,
            lm_challenge_response_bytes_len,
            current_payload_offset
        )
        current_payload_offset += lm_challenge_response_bytes_len

        nt_challenge_response_bytes = bytes(self.nt_challenge_response)
        nt_challenge_response_bytes_len = len(nt_challenge_response_bytes)
        nt_challenge_response_fields = struct_pack(
            '<HHI',
            nt_challenge_response_bytes_len,
            nt_challenge_response_bytes_len,
            current_payload_offset
        )
        current_payload_offset += nt_challenge_response_bytes_len

        # TODO: "DomainName MUST be encoded in the negotiated character set."

        domain_name_bytes: bytes = self.domain_name.encode(encoding='utf-16-le')
        domain_name_bytes_len = len(domain_name_bytes)
        domain_name_fields = struct_pack('<HHI', domain_name_bytes_len, domain_name_bytes_len, current_payload_offset)
        current_payload_offset += domain_name_bytes_len

        # TODO: "UserName MUST be encoded in the negotiated character set."

        user_name_bytes = str.encode(self.user_name, encoding='utf-16-le')
        user_name_bytes_len = len(user_name_bytes)
        user_name_fields = struct_pack('<HHI', user_name_bytes_len, user_name_bytes_len, current_payload_offset)
        current_payload_offset += user_name_bytes_len

        # TODO: "Workstation MUST be encoded in the negotiated character set."

        workstation_bytes: bytes = self.workstation_name.encode(encoding='utf-16-le')
        workstation_bytes_len = len(workstation_bytes)
        workstation_fields = struct_pack('<HHI', workstation_bytes_len, workstation_bytes_len, current_payload_offset)
        current_payload_offset += workstation_bytes_len

        encrypted_random_session_key_len = len(self.encrypted_random_session_key)
        encrypted_random_session_key_fields = struct_pack(
            '<HHI',
            encrypted_random_session_key_len,
            encrypted_random_session_key_len,
            current_payload_offset
        )
        current_payload_offset += encrypted_random_session_key_len

        return b''.join([
            self.SIGNATURE,
            struct_pack('<I', self.MESSAGE_TYPE_ID),
            lm_challenge_response_fields,
            nt_challenge_response_fields,
            domain_name_fields,
            user_name_fields,
            workstation_fields,
            encrypted_random_session_key_fields,
            struct_pack('<I', int(self.negotiate_flags)),
            version_bytes,
            mic_bytes,
            self.lm_challenge_response,
            nt_challenge_response_bytes,
            domain_name_bytes,
            user_name_bytes,
            workstation_bytes,
            self.encrypted_random_session_key
        ])
