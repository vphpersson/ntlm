from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from abc import ABC, abstractmethod
from struct import unpack_from as struct_unpack_from, pack as struct_pack


@dataclass
class NTLMSSPMessageSignature(ABC):
    VERSION: ClassVar[int] = 1

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes, base_offset: int = 0, strict: bool = True):
        # TODO: Check to see if the instance on which this was called is not the abstract class?
        #   In which case, throw an `NotImplementedError`?
        if strict and (version := struct_unpack_from('<I', buffer=data, offset=base_offset)) != cls.VERSION:
            # TODO: Use proper exception (the parse one?)
            raise ValueError

    @abstractmethod
    def __bytes__(self) -> bytes:
        raise NotImplementedError


@dataclass
class NTLMSSPMessageSignatureESS(NTLMSSPMessageSignature):
    checksum: bytes
    seq_num: int

    @classmethod
    def from_bytes(cls, data: bytes, base_offset: int = 0, strict: bool = True):
        super().from_bytes(data=data, base_offset=base_offset, strict=strict)

        return cls(
            checksum=data[base_offset+4:base_offset+12],
            seq_num=struct_unpack_from('<I', buffer=data, offset=base_offset+12)[0]
        )

    def __bytes__(self) -> bytes:
        return b''.join([
            struct_pack('<I', self.VERSION),
            self.checksum,
            struct_pack('<I', self.seq_num)
        ])
