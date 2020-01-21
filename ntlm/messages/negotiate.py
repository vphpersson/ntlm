from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, ClassVar
from struct import unpack as struct_unpack, pack as struct_pack

from ntlm.messages import Message, register_ntlm_message
from ntlm.structures.version import Version
from ntlm.structures.negotiate_flags import NegotiateFlags
from ntlm.internal_utils import get_message_bytes_data_str
from ntlm.exceptions import MalformedNegotiateMessageError


@register_ntlm_message
@dataclass
class NegotiateMessage(Message):
    MESSAGE_TYPE_ID: ClassVar[int] = 1
    _MALFORMED_EXCEPTION_CLASS: ClassVar = MalformedNegotiateMessageError

    negotiate_flags: NegotiateFlags
    domain_name: Optional[str] = None
    workstation_name: Optional[str] = None
    os_version: Optional[Version] = None

    @classmethod
    def _from_bytes(cls, data: bytes) -> NegotiateMessage:
        flags = NegotiateFlags.from_int(struct_unpack('<I', data[12:16])[0])

        return cls(
            negotiate_flags=flags,
            domain_name=get_message_bytes_data_str(
                data,
                *struct_unpack('<HHI', data[16:24])
            ) if flags.negotiate_oem_domain_supplied else None,
            workstation_name=get_message_bytes_data_str(
                data,
                *struct_unpack('<HHI', data[24:32])
            ) if flags.negotiate_oem_workstation_supplied else None,
            os_version=Version(*struct_unpack('<BBh', data[32:36])) if flags.negotiate_version else None
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
            Message.SIGNATURE,
            struct_pack('<I', NegotiateMessage.MESSAGE_TYPE_ID),
            struct_pack('<I', int(self.negotiate_flags)),
            domain_name_fields,
            workstation_fields,
            version_bytes,
            domain_bytes,
            workstation_bytes
        ])
