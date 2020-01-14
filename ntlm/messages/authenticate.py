from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, ClassVar, Union
from struct import unpack as struct_unpack, pack as struct_pack

from ntlm.messages import NTLMMessage
from ntlm.structures.negotiate_flags import NegotiateFlags
from ntlm.structures.ntlmv2_response import NTLMv2Response
from ntlm.structures.version import Version
from ntlm.internal_utils import get_message_bytes_data, get_message_bytes_data_str
from ntlm.exceptions import MalformedAuthenticateMessageError


@dataclass
class AuthenticateMessage(NTLMMessage):
    lm_challenge_response: bytes
    nt_challenge_response: Union[NTLMv2Response, bytes]
    domain_name: str
    user_name: str
    negotiate_flags: NegotiateFlags
    mic: Optional[bytes] = 16 * b'\x00'
    workstation_name: Optional[str] = None
    encrypted_random_session_key: bytes = b''
    os_version: Optional[Version] = None

    message_type_id: ClassVar[int] = 3
    _malformed_exception_class: ClassVar = MalformedAuthenticateMessageError

    @classmethod
    def from_bytes(cls, message_bytes: bytes) -> AuthenticateMessage:
        cls.check_signature(signature_data=struct_unpack('<8s', message_bytes[0:8])[0])
        cls.check_message_type(
            message_type_id=struct_unpack('<I', message_bytes[8:12])[0],
            message_bytes=message_bytes
        )

        flags = NegotiateFlags.from_mask(struct_unpack('<I', message_bytes[60:64])[0])

        nt_challenge_response_bytes: bytes = get_message_bytes_data(
            message_bytes,
            *struct_unpack('<HHI', message_bytes[20:28])
        )

        return cls(
            lm_challenge_response=get_message_bytes_data(message_bytes, *struct_unpack('<HHI', message_bytes[12:20])),
            nt_challenge_response=(
                NTLMv2Response.from_bytes(nt_challenge_response_bytes)
                if len(nt_challenge_response_bytes) > 24 else nt_challenge_response_bytes
            ),
            domain_name=get_message_bytes_data_str(message_bytes, *struct_unpack('<HHI', message_bytes[28:36])),
            user_name=get_message_bytes_data_str(message_bytes, *struct_unpack('<HHI', message_bytes[36:44])),
            workstation_name=get_message_bytes_data_str(message_bytes, *struct_unpack('<HHI', message_bytes[44:52])),
            encrypted_random_session_key=get_message_bytes_data(
                message_bytes,
                *struct_unpack('<HHI', message_bytes[52:60])
            ) if flags.negotiate_key_exch else b'',
            negotiate_flags=flags,
            os_version=Version(*struct_unpack('<BBHxxxx', message_bytes[64:72])) if flags.negotiate_version else None,
            # TODO: The MIC can be omitted! Support this case!
            mic=message_bytes[72:88]
        )

    def __bytes__(self) -> bytes:
        # TODO: Not sure `negotiate_version` is actually a requirement.
        version_bytes: bytes = bytes(self.os_version) if self.negotiate_flags.negotiate_version else b''
        mic_bytes: bytes = self.mic if self.mic is not None else b''

        if version_bytes and mic_bytes:
            current_payload_offset = 88
        elif version_bytes and not mic_bytes:
            current_payload_offset = 72
        elif not version_bytes and mic_bytes:
            current_payload_offset = 80
        elif not version_bytes and not mic_bytes:
            current_payload_offset = 64
        else:
            raise ValueError

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

        domain_name_bytes = str.encode(
            self.domain_name if self.negotiate_flags.negotiate_oem_domain_supplied else '', encoding='utf-16-le'
        )
        domain_name_bytes_len = len(domain_name_bytes)
        domain_name_fields = struct_pack('<HHI', domain_name_bytes_len, domain_name_bytes_len, current_payload_offset)
        current_payload_offset += domain_name_bytes_len

        # TODO: "UserName MUST be encoded in the negotiated character set."

        user_name_bytes = str.encode(self.user_name, encoding='utf-16-le')
        user_name_bytes_len = len(user_name_bytes)
        user_name_fields = struct_pack('<HHI', user_name_bytes_len, user_name_bytes_len, current_payload_offset)
        current_payload_offset += user_name_bytes_len

        # TODO: "Workstation MUST be encoded in the negotiated character set."

        workstation_bytes = str.encode(
            self.workstation_name
            if self.negotiate_flags.negotiate_oem_workstation_supplied else '', encoding='utf-16-le'
        )
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
            NTLMMessage.signature,
            struct_pack('<I', self.message_type_id),
            lm_challenge_response_fields,
            nt_challenge_response_fields,
            domain_name_fields,
            user_name_fields,
            workstation_fields,
            encrypted_random_session_key_fields,
            struct_pack('<I', self.negotiate_flags.to_mask().value),
            version_bytes,
            mic_bytes,
            self.lm_challenge_response,
            nt_challenge_response_bytes,
            domain_name_bytes,
            user_name_bytes,
            workstation_bytes,
            self.encrypted_random_session_key
        ])
