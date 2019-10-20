from __future__ import annotations
from dataclasses import dataclass

from .ntlmv2_client_challenge import NTLMv2ClientChallenge


@dataclass
class NTLMv2Response:
    """
    [MS-NLMP]: NTLM2 V2 Response: NTLMv2_RESPONSE
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/d43e2224-6fc3-449d-9f37-b90b55a29c80
    """

    response: bytes
    ntlmv2_client_challenge: NTLMv2ClientChallenge

    @classmethod
    def from_bytes(cls, data: bytes) -> 'NTLMv2Response':
        return cls(
            response=data[:16],
            ntlmv2_client_challenge=NTLMv2ClientChallenge.from_bytes(data[16:])
        )

    def __bytes__(self) -> bytes:
        return self.response + bytes(self.ntlmv2_client_challenge)
