from dataclasses import dataclass
from struct import unpack as struct_unpack, pack as struct_pack

from ntlm.structures.av_pair import AVPairSequence


@dataclass
class NTLMv2ClientChallenge:
    """
    [MS-NLMP]: NTLM v2: NTLMv2_CLIENT_CHALLENGE
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/aee311d6-21a7-4470-92a5-c4ecb022a87b
    """

    # NOTE: Must be `FILETIME`.
    time_stamp: bytes
    challenge_from_client: bytes
    av_pairs: AVPairSequence

    @property
    def resp_type(self) -> int:
        return 0x01

    @property
    def hi_resp_type(self) -> int:
        return 0x01

    @classmethod
    def from_bytes(cls, data: bytes) -> 'NTLMv2ClientChallenge':

        resp_type: bytes = struct_unpack('<B', data[:1])[0]
        if resp_type != 0x01:
            # TODO: Use proper exception.
            raise ValueError

        hi_resp_type: bytes = struct_unpack('<B', data[1:2])[0]
        if hi_resp_type != 0x01:
            # TODO: Use proper exception.
            raise ValueError

        reserved_1: bytes = data[2:4]
        if reserved_1 != b'\x00\x00':
            # TODO: Use proper exception.
            raise ValueError

        reserved_2: bytes = data[4:8]
        if reserved_2 != b'\x00\x00\x00\x00':
            # TODO: Use proper exception.
            raise ValueError

        reserved_3: bytes = data[24:28]
        if reserved_3 != b'\x00\x00\x00\x00':
            # TODO: Use proper exception.
            raise ValueError

        return cls(
            time_stamp=data[8:16],
            challenge_from_client=data[16:24],
            av_pairs=AVPairSequence.from_bytes(data=data[28:])
        )

    def __bytes__(self) -> bytes:
        return b''.join((
            struct_pack('<B', self.resp_type),
            struct_pack('<B', self.hi_resp_type),
            6 * b'\x00',
            self.time_stamp,
            self.challenge_from_client,
            4 * b'\x00',
            bytes(self.av_pairs),
            # TODO: From where did I get these? Sure they should not be here?
            4 * b'\x00'
        ))
