from typing import Union, ByteString, SupportsBytes
from enum import Enum
from hashlib import md5 as hashlib_md5
from struct import pack as struct_pack
from hmac import new as hmac_new

from Crypto.Cipher import ARC4

from ntlm.messages.negotiate import NegotiateMessage
from ntlm.messages.authenticate import AuthenticateMessage
from ntlm.messages.challenge import ChallengeMessage
from ntlm.structures.negotiate_flags import NegotiateFlags
from ntlm.structures.ntlmssp_message_signature import NTLMSSPMessageSignature, NTLMSSPMessageSignatureESS

CLIENT_TO_SERVER_SIGNING_KEY_MAGIC_CONSTANT = b'session key to client-to-server signing key magic constant\x00'
SERVER_TO_CLIENT_SIGNING_KEY_MAGIC_CONSTANT = b'session key to server-to-client signing key magic constant\x00'
CLIENT_TO_SERVER_SEALING_KEY_MAGIC_CONSTANT = b'session key to client-to-server sealing key magic constant\x00'
SERVER_TO_CLIENT_SEALING_KEY_MAGIC_CONSTANT = b'session key to server-to-client sealing key magic constant\x00'


class Mode(Enum):
    SERVER = 'server'
    CLIENT = 'client'


def make_sign_key(negotiate_flags: NegotiateFlags, exported_session_key: bytes, mode: Mode) -> bytes:
    """
    Produce a signing key.

    :param negotiate_flags: Negotiated flags.
    :param exported_session_key: A randomly generated session key.
    :param mode: The local machine that will perform signing using the key.
    :return: A signing key.
    """

    if not negotiate_flags.negotiate_extended_sessionsecurity:
        return b''

    if mode is Mode.CLIENT:
        sign_key = hashlib_md5(exported_session_key + CLIENT_TO_SERVER_SIGNING_KEY_MAGIC_CONSTANT).digest()
    elif mode is Mode.SERVER:
        sign_key = hashlib_md5(exported_session_key + SERVER_TO_CLIENT_SIGNING_KEY_MAGIC_CONSTANT).digest()
    else:
        raise ValueError(f'Unsupported mode value {mode.value}')

    return sign_key


def make_seal_key(negotiate_flags: NegotiateFlags, exported_session_key: bytes, mode: Mode) -> bytes:
    """
    Produce a sealing key.

    :param negotiate_flags: Negotiated flags.
    :param exported_session_key: A randomly generated session key.
    :param mode: The local machine that will perform sealing using the key.
    :return: A sealing key.
    """

    if negotiate_flags.negotiate_extended_sessionsecurity:
        if negotiate_flags.negotiate_128:
            pre_seal_key = exported_session_key
        elif negotiate_flags.negotiate_56:
            pre_seal_key = exported_session_key[:7]
        else:
            pre_seal_key = exported_session_key[:5]

        if mode is Mode.CLIENT:
            seal_key = hashlib_md5(pre_seal_key + CLIENT_TO_SERVER_SEALING_KEY_MAGIC_CONSTANT).digest()
        elif mode is Mode.SERVER:
            seal_key = hashlib_md5(pre_seal_key + SERVER_TO_CLIENT_SEALING_KEY_MAGIC_CONSTANT).digest()
        else:
            raise ValueError(f'Unsupported mode value {mode.value}')

    # NOTE: Actual condition:
    #
    #   (NTLMSSP_NEGOTIATE_LM_KEY is set in NegFlg)
    #       or ((NTLMSSP_NEGOTIATE_DATAGRAM is set in NegFlg) and (NTLMRevisionCurrent >= NTLMSSP_REVISION_W2K3)))
    #
    # `NTLMSSP_REVISION_W2K3` can be found in the `VERSION` structure, but it is supposed to be set to a static value,
    # 0x0F, indicating that version 15 of the NTLMSSP is in use.
    elif negotiate_flags.negotiate_lm_key or negotiate_flags.negotiate_datagram:
        if negotiate_flags.negotiate_56:
            seal_key = exported_session_key[:7] + b'\xa0'
        else:
            seal_key = exported_session_key[:5] + b'\xe5\x38\xb0'
    else:
        seal_key = exported_session_key

    return seal_key


def _sign_with_extended_session_security(
    cipher_handle: ARC4,
    signing_key: bytes,
    data: bytes,
    sequence_number: int,
    negotiate_flags: NegotiateFlags
) -> NTLMSSPMessageSignatureESS:

    sequence_number_bytes = struct_pack('<I', sequence_number)
    checksum: bytes = hmac_new(
        key=signing_key,
        msg=sequence_number_bytes + data,
        digestmod='md5'
    ).digest()[:8]

    if negotiate_flags.negotiate_key_exch:
        checksum = cipher_handle.encrypt(plaintext=checksum)

    return NTLMSSPMessageSignatureESS(checksum=checksum, seq_num=sequence_number)


def _sign_without_extended_session_security(
    cipher_handle: ARC4,
    signing_key: bytes,
    data: bytes,
    sequence_number: int
) -> NTLMSSPMessageSignature:
    # TODO: Implement.
    raise NotImplementedError


def sign(
    cipher_handle: ARC4,
    signing_key: bytes,
    data: bytes,
    sequence_number: int,
    negotiate_flags: NegotiateFlags
) -> NTLMSSPMessageSignature:
    """

    :param cipher_handle:
    :param signing_key:
    :param data:
    :param sequence_number:
    :param negotiate_flags:
    :return:
    """

    if negotiate_flags.negotiate_extended_sessionsecurity:
        return _sign_with_extended_session_security(
            cipher_handle=cipher_handle,
            signing_key=signing_key,
            data=data,
            sequence_number=sequence_number,
            negotiate_flags=negotiate_flags
        )
    else:
        return _sign_without_extended_session_security(
            cipher_handle=cipher_handle,
            signing_key=signing_key,
            data=data,
            sequence_number=sequence_number
        )


def calculate_authenticate_message_mic(
    negotiate_message: Union[ByteString, NegotiateMessage],
    challenge_message: Union[ByteString, ChallengeMessage],
    authenticate_message: Union[ByteString, AuthenticateMessage],
    exported_session_key: ByteString
) -> bytes:
    """
    Calculate the MIC for an NTLM authenticate message.

    The provided authenticate message should have its MIC field set to 16 null bytes.

    :param negotiate_message: A representation of an NTLM negotiate message.
    :param challenge_message: A representation of an NTLM challenge message.
    :param authenticate_message: A representation of an NTLM challenge message.
    :param exported_session_key:
    :return: A NTLM authenticate message MIC.
    """

    return hmac_new(
        key=exported_session_key,
        msg=bytes(negotiate_message) + bytes(challenge_message) + bytes(authenticate_message),
        digestmod='md5'
    ).digest()
