from __future__ import annotations
from typing import ByteString, List
from struct import unpack_from as struct_unpack_from

from ntlm.structures.av_pairs import AVPair
from ntlm.structures.av_pairs.eol import EOLAVPair
from ntlm.exceptions import MultipleEOLError, EOLNotObservedError


class AVPairSequence(list):
    """
    A list of `AVPair`s.
    """

    def __init__(self, iterable=()):
        super().__init__(iterable)

    def add_av_pair(self, av_pair: AVPair) -> None:
        if isinstance(av_pair, EOLAVPair):
            if len(self) == 0 or not isinstance(self[-1], EOLAVPair):
                self.append(av_pair)
            # TODO: Should I let one add another `EOLAVPair` if one really wants to?
        else:
            eol_av_pair = EOLAVPair() if len(self) == 0 else self.pop()
            self.extend([av_pair, eol_av_pair])

    @classmethod
    def from_bytes(
        cls,
        buffer: ByteString,
        base_offset: int = 0,
        strict: bool = True,
        break_on_eol: bool = False
    ) -> AVPairSequence:

        buffer = memoryview(buffer)[base_offset:]

        offset = 0
        eol_observed = False
        av_pairs_list: List[AVPair] = []

        while offset + 4 <= len(buffer):
            av_pair = AVPair.from_bytes(buffer=buffer[offset:])
            av_pairs_list.append(av_pair)

            if isinstance(av_pair, EOLAVPair):
                if strict and eol_observed:
                    raise MultipleEOLError

                eol_observed = True
                if break_on_eol:
                    break

            av_len: int = struct_unpack_from('<H', buffer=buffer, offset=offset+2)[0]
            offset += 4 + av_len

        if strict and not eol_observed:
            raise EOLNotObservedError

        return cls(av_pairs_list)

    def __bytes__(self) -> bytes:
        return b''.join(bytes(av_pair) for av_pair in self.__iter__())
