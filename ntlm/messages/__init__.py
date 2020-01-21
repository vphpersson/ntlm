from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Type, Dict
from abc import ABC, abstractmethod
from struct import unpack as struct_unpack

from ntlm.exceptions import MalformedSignatureError, UnexpectedMessageTypeError, \
    MalformedMessageError


@dataclass
class Message(ABC):
    SIGNATURE: ClassVar[bytes] = b'NTLMSSP\x00'
    MESSAGE_TYPE_ID_TO_MESSAGE_CLASS: ClassVar[Dict[int, Type[Message]]] = {}

    MESSAGE_TYPE_ID: ClassVar[int] = NotImplemented
    MALFORMED_MESSAGE_ERROR_CLASS: ClassVar[Type[MalformedMessageError]] = NotImplementedError

    @classmethod
    def from_bytes(cls, data: bytes) -> Message:

        import ntlm.messages.negotiate
        import ntlm.messages.challenge
        import ntlm.messages.authenticate

        signature_data: bytes = struct_unpack('<8s', data[0:8])[0]
        if signature_data != cls.SIGNATURE:
            raise MalformedSignatureError(observed_signature=signature_data)

        message_type_id: int = struct_unpack('<I', data[8:12])[0]

        if cls != Message:
            if message_type_id != cls.MESSAGE_TYPE_ID:
                raise UnexpectedMessageTypeError(
                    observed_ntlm_message_type_id=message_type_id,
                    expected_message_type_id=cls.MESSAGE_TYPE_ID
                )
            return cls._from_bytes(data=data)
        else:
            return cls.MESSAGE_TYPE_ID_TO_MESSAGE_CLASS[message_type_id].from_bytes(data=data)

    @classmethod
    @abstractmethod
    def _from_bytes(cls, data: bytes) -> Message:
        raise NotImplementedError

    @abstractmethod
    def __bytes__(self) -> bytes:
        raise NotImplementedError


def register_ntlm_message(cls: Type[Message]):
    cls.MESSAGE_TYPE_ID_TO_MESSAGE_CLASS[cls.MESSAGE_TYPE_ID] = cls
    return cls
