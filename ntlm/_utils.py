from typing import ByteString


def get_message_bytes_data(buffer: ByteString, length: int, alloc: int, offset: int, base_offset: int = 0) -> bytes:
    return bytes(buffer[base_offset+offset:base_offset+offset+length])


def get_message_bytes_data_str(buffer: ByteString, length: int, alloc: int, offset: int, base_offset: int = 0) -> str:
    # TODO: The encoding isn't necessarily utf-16-le...
    return get_message_bytes_data(buffer, length, alloc, base_offset+offset).decode(encoding='utf-16-le')
