from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Type, Dict, ByteString
from abc import ABC, abstractmethod
from struct import unpack_from as struct_unpack_from

from ntlm.exceptions import MalformedSignatureError, UnexpectedMessageTypeError, MalformedMessageError


@dataclass
class Message(ABC):
    SIGNATURE: ClassVar[bytes] = b'NTLMSSP\x00'
    MESSAGE_TYPE_ID_TO_MESSAGE_CLASS: ClassVar[Dict[int, Type[Message]]] = {}

    MESSAGE_TYPE_ID: ClassVar[int] = NotImplemented
    MALFORMED_MESSAGE_ERROR_CLASS: ClassVar[Type[MalformedMessageError]] = NotImplementedError

    @classmethod
    def from_bytes(cls, buffer: ByteString, base_offset: int = 0, strict: bool = True) -> Message:

        import ntlm.messages.negotiate
        import ntlm.messages.challenge
        import ntlm.messages.authenticate

        buffer = memoryview(buffer)[base_offset:]

        if strict and (signature := struct_unpack_from('<8s', buffer=buffer, offset=0)[0]) != cls.SIGNATURE:
            raise MalformedSignatureError(observed_signature=signature)

        message_type_id: int = struct_unpack_from('<I', buffer=buffer, offset=8)[0]

        if cls != Message:
            if message_type_id != cls.MESSAGE_TYPE_ID:
                raise UnexpectedMessageTypeError(
                    observed_ntlm_message_type_id=message_type_id,
                    expected_message_type_id=cls.MESSAGE_TYPE_ID
                )
            return cls._from_bytes(buffer=buffer, strict=strict)
        else:
            return cls.MESSAGE_TYPE_ID_TO_MESSAGE_CLASS[message_type_id].from_bytes(buffer=buffer, strict=strict)

    @classmethod
    @abstractmethod
    def _from_bytes(cls, buffer: memoryview, strict: bool = True) -> Message:
        raise NotImplementedError

    @abstractmethod
    def __bytes__(self) -> bytes:
        raise NotImplementedError

    @classmethod
    def register(cls, ntlm_message_class: Type[Message]) -> Type[Message]:
        cls.MESSAGE_TYPE_ID_TO_MESSAGE_CLASS[ntlm_message_class.MESSAGE_TYPE_ID] = ntlm_message_class
        return ntlm_message_class
