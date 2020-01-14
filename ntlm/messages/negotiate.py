from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, ClassVar
from struct import unpack as struct_unpack, pack as struct_pack

from ntlm.messages import NTLMMessage
from ntlm.structures.version import Version
from ntlm.structures.negotiate_flags import NegotiateFlags
from ntlm.internal_utils import get_message_bytes_data_str
from ntlm.exceptions import MalformedNegotiateMessageError


@dataclass
class NegotiateMessage(NTLMMessage):
    negotiate_flags: NegotiateFlags
    domain_name: Optional[str] = None
    workstation_name: Optional[str] = None
    os_version: Optional[Version] = None

    message_type_id: ClassVar[int] = 1
    _malformed_exception_class: ClassVar = MalformedNegotiateMessageError

    @classmethod
    def from_bytes(cls, message_bytes: bytes) -> 'NegotiateMessage':

        cls.check_signature(signature_data=struct_unpack('<8s', message_bytes[0:8])[0])
        cls.check_message_type(
            message_type_id=struct_unpack('<I', message_bytes[8:12])[0],
            message_bytes=message_bytes
        )

        flags = NegotiateFlags.from_int(struct_unpack('<I', message_bytes[12:16])[0])

        return cls(
            negotiate_flags=flags,
            domain_name=get_message_bytes_data_str(
                message_bytes,
                *struct_unpack('<HHI', message_bytes[16:24])
            ) if flags.negotiate_oem_domain_supplied else None,
            workstation_name=get_message_bytes_data_str(
                message_bytes,
                *struct_unpack('<HHI', message_bytes[24:32])
            ) if flags.negotiate_oem_workstation_supplied else None,
            os_version=Version(*struct_unpack('<BBh', message_bytes[32:36])) if flags.negotiate_version else None
        )

    # TODO: Consider `negotiate_extended_sessionsecurity`. May have to reconsider all of this in the future.

    @classmethod
    def make_ntlm_v1_negotiate(
            cls,
            domain_name: Optional[str] = None,
            workstation_name: Optional[str] = None,
            os_version: Optional[Version] = None
    ) -> 'NegotiateMessage':
        """

        :param domain_name:
        :param workstation_name:
        :param os_version:
        :return:
        """

        return cls(
            negotiate_flags=NegotiateFlags(
                request_target=True,
                negotiate_ntlm=True,
                negotiate_always_sign=True,
                negotiate_unicode=True,
                negotiate_version=os_version is not None,
                negotiate_oem_domain_supplied=domain_name is not None,
                negotiate_oem_workstation_supplied=workstation_name is not None
            ),
            domain_name=domain_name,
            workstation_name=workstation_name,
            os_version=os_version
        )

    @classmethod
    def make_ntlm_v2_negotiate(
            cls,
            domain_name: Optional[str] = None,
            workstation_name: Optional[str] = None,
            os_version: Optional[Version] = None
    ) -> 'NegotiateMessage':
        """

        :param domain_name:
        :param workstation_name:
        :param os_version:
        :return:
        """

        return cls(
            negotiate_flags=NegotiateFlags(
                request_target=True,
                negotiate_ntlm=True,
                negotiate_always_sign=True,
                negotiate_unicode=True,
                negotiate_key_exch=True,
                negotiate_version=os_version is not None,
                negotiate_oem_domain_supplied=domain_name is not None,
                negotiate_oem_workstation_supplied=workstation_name is not None
            ),
            domain_name=domain_name,
            workstation_name=workstation_name,
            os_version=os_version
        )

    def __bytes__(self) -> bytes:

        current_payload_offset = 32

        version_bytes = bytes(self.os_version) if self.negotiate_flags.negotiate_version else b''
        current_payload_offset += len(version_bytes)

        domain_bytes = str.encode(
            self.domain_name if self.negotiate_flags.negotiate_oem_domain_supplied else '', encoding='utf-16-le'
        )
        domain_bytes_len = len(domain_bytes)
        domain_name_fields = struct_pack('<HHI', domain_bytes_len, domain_bytes_len, current_payload_offset)
        current_payload_offset += domain_bytes_len

        workstation_bytes = str.encode(
            self.workstation_name if self.negotiate_flags.negotiate_oem_workstation_supplied else '',
            encoding='utf-16-le'
        )
        workstation_bytes_len = len(workstation_bytes)
        workstation_fields = struct_pack(
            '<HHI',
            workstation_bytes_len,
            workstation_bytes_len,
            current_payload_offset
        )
        current_payload_offset += workstation_bytes_len

        return b''.join([
            NTLMMessage.signature,
            struct_pack('<I', NegotiateMessage.message_type_id),
            struct_pack('<I', int(self.negotiate_flags)),
            domain_name_fields,
            workstation_fields,
            version_bytes,
            domain_bytes,
            workstation_bytes
        ])
