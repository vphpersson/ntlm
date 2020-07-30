from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, ByteString
from struct import pack as struct_pack

from ntlm.structures.av_pair_sequence import AVPairSequence


@dataclass
class NTLMv2ClientChallenge:
    """
    [MS-NLMP]: NTLM v2: NTLMv2_CLIENT_CHALLENGE
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/aee311d6-21a7-4470-92a5-c4ecb022a87b
    """

    RESP_TYPE: ClassVar[int] = 0x01
    HI_RESP_TYPE: ClassVar[int] = 0x1
    _RESERVED_1: ClassVar[bytes] = bytes(2)
    _RESERVED_2: ClassVar[bytes] = bytes(4)
    _RESERVED_3: ClassVar[bytes] = bytes(4)

    # NOTE: Must be `FILETIME`.
    time_stamp: bytes
    challenge_from_client: bytes
    av_pairs: AVPairSequence

    @classmethod
    def from_bytes(cls, buffer: ByteString, base_offset: int = 0, strict: bool = True) -> NTLMv2ClientChallenge:
        buffer = memoryview(buffer)[base_offset:]

        if strict:
            if (resp_type := buffer[0]) != cls.RESP_TYPE:
                # TODO: Use proper exception.
                raise ValueError

            if (hi_resp_type := buffer[1]) != cls.HI_RESP_TYPE:
                # TODO: Use proper exception.
                raise ValueError

            if (reserved_1 := bytes(buffer[2:4])) != cls._RESERVED_1:
                # TODO: Use proper exception.
                raise ValueError

            if (reserved_2 := bytes(buffer[4:8])) != cls._RESERVED_2:
                # TODO: Use proper exception.
                raise ValueError

            if (reserved_3 := bytes(buffer[24:28])) != cls._RESERVED_3:
                # TODO: Use proper exception.
                raise ValueError

        # TODO: I don't know how I can check if there are four null bytes after the `AVPair` sequence in a nice way.

        return cls(
            time_stamp=bytes(buffer[8:16]),
            challenge_from_client=bytes(buffer[16:24]),
            av_pairs=AVPairSequence.from_bytes(buffer=buffer[28:], break_on_eol=True)
        )

    def __bytes__(self) -> bytes:
        # TODO: Use `ClassVar` constants for the reserved values.
        return b''.join((
            struct_pack('<B', self.RESP_TYPE),
            struct_pack('<B', self.HI_RESP_TYPE),
            bytes(6),
            self.time_stamp,
            self.challenge_from_client,
            bytes(4),
            bytes(self.av_pairs),
            bytes(4)
        ))
