from typing import Optional


class MalformedMessageError(Exception):
    def __init__(self, message: str, message_bytes: Optional[bytes] = None):
        super().__init__(message)
        self.message_bytes: Optional[bytes] = message_bytes


class MalformedNegotiateMessageError(MalformedMessageError):
    def __init__(self, message_bytes: bytes):
        super().__init__(message='Error while parsing a supposed negotiate message.', message_bytes=message_bytes)


class MalformedChallengeMessageError(MalformedMessageError):
    def __init__(self, message_bytes: bytes):
        super().__init__(message='Error while parsing a supposed challenge message.', message_bytes=message_bytes)


class MalformedAuthenticateMessageError(MalformedMessageError):
    def __init__(self, message_bytes: bytes):
        super().__init__(message='Error while parsing a supposed authenticate message.', message_bytes=message_bytes)


class UnexpectedMessageTypeError(MalformedMessageError):
    def __init__(self, observed_ntlm_message_type_id: int, expected_message_type_id: int):
        super().__init__(
            message=f'Unexpected message type id: {observed_ntlm_message_type_id}. '
            f'Expected: {expected_message_type_id})'
        )


class MalformedSignatureError(MalformedMessageError):
    def __init__(self, observed_signature: bytes):
        super().__init__(message=f'Malformed NTLM signature: {observed_signature}')
