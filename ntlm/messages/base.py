from dataclasses import dataclass
from typing import ClassVar, Optional, Type
from abc import ABC, abstractmethod

from ..exceptions import MalformedNTLMSignatureError, UnexpectedMessageTypeError, MalformedNTLMMessageError


@dataclass
class NTLMMessage(ABC):
    signature: ClassVar[bytes] = b'NTLMSSP\x00'
    message_type_id: ClassVar[int] = NotImplemented
    _malformed_exception_class: ClassVar[Type[MalformedNTLMMessageError]] = NotImplemented

    @classmethod
    def check_signature(cls, signature_data: bytes) -> None:
        if signature_data != cls.signature:
            raise cls._malformed_exception_class from MalformedNTLMSignatureError(observed_signature=signature_data)

    @classmethod
    @abstractmethod
    def from_bytes(cls, message_bytes: bytes) -> 'NTLMMessage':
        pass

    @abstractmethod
    def __bytes__(self) -> bytes:
        pass

    @classmethod
    def check_message_type(cls, message_type_id: int, message_bytes: Optional[bytes] = None) -> None:
        if message_type_id != cls.message_type_id:
            raise cls._malformed_exception_class(message_bytes=message_bytes) from UnexpectedMessageTypeError(
                observed_ntlm_message_type_id=message_type_id,
                expected_message_type_id=cls.message_type_id
            )
