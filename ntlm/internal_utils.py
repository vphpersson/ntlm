def get_message_bytes_data(bytes_data: bytes, length: int, alloc: int, offset: int) -> bytes:
    return bytes_data[offset:offset+length]


def get_message_bytes_data_str(bytes_data: bytes, length: int, alloc: int, offset: int) -> str:
    # TODO: The encoding isn't necessarily utf-16-le...
    return get_message_bytes_data(bytes_data, length, alloc, offset).decode(encoding='utf-16-le')
