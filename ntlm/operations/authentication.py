from typing import Optional, Tuple, Union
from hmac import new as hmac_new
from hashlib import md5 as hashlib_md5
from secrets import token_bytes
from datetime import datetime

from Crypto.Cipher import DES
from msdsalgs.time import datetime_to_filetime
from msdsalgs.hashing import compute_lm_hash, compute_nt_hash
from msdsalgs.crypto import transform_des_key

from ntlm.structures.av_pair import AVPairSequence
from ntlm.structures.ntlmv2_response import NTLMv2Response
from ntlm.structures.ntlmv2_client_challenge import NTLMv2ClientChallenge


def compute_net_ntlm_v2_hash(key: bytes, server_challenge_bytes: bytes, client_temp_bytes: bytes) -> bytes:
    """
    Compute a Net-NTLMv2 hash.

    :param key:
    :param server_challenge_bytes:
    :param client_temp_bytes:
    :return:
    """
    return hmac_new(key=key, msg=server_challenge_bytes + client_temp_bytes, digestmod=hashlib_md5).digest()


def compute_response(
    response_key_nt: bytes,
    response_key_lm: bytes,
    server_challenge: bytes,
    server_name: AVPairSequence,
    client_challenge: Optional[bytes] = None,
    time: Optional[bytes] = None
) -> Tuple[NTLMv2Response, bytes, bytes]:
    """


    [MS-NLMP]: NTLM v2 Authentication
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3

    :param response_key_nt:
    :param response_key_lm:
    :param server_challenge:
    :param server_name:
    :param client_challenge:
    :param time: A byte representation of a FILETIME timestamp.
    :return:
    """

    client_challenge = client_challenge if client_challenge is not None else token_bytes(nbytes=8)
    if len(client_challenge) != 8:
        # TODO: Use proper exception.
        raise ValueError

    ntlm_v2_client_challenge = NTLMv2ClientChallenge(
        time_stamp=time if time is not None else datetime_to_filetime(datetime.now()),
        challenge_from_client=client_challenge,
        av_pairs=server_name
    )
    # TODO: Figure out where it is said that there should be four null bytes at the end.
    temp = bytes(ntlm_v2_client_challenge) + bytes(4)

    nt_proof_str: bytes = compute_net_ntlm_v2_hash(
        key=response_key_nt,
        server_challenge_bytes=server_challenge,
        client_temp_bytes=temp
    )

    # `NtChallengeResponse`, `LmChallengeResponse`, and `SessionBaseKey`.
    return (
        NTLMv2Response(response=nt_proof_str, ntlmv2_client_challenge=ntlm_v2_client_challenge),
        hmac_new(
            key=response_key_lm,
            msg=server_challenge + client_challenge,
            digestmod=hashlib_md5
        ).digest() + client_challenge,
        hmac_new(key=response_key_nt, msg=nt_proof_str, digestmod=hashlib_md5).digest()
    )


def _produce_lm_or_ntlm_response(hash_bytes: bytes, server_challenge: bytes) -> bytes:
    """

    :param hash_bytes:
    :param server_challenge:
    :return:
    """
    des_base = hash_bytes.ljust(21, b'\x00')

    return b''.join((
        DES.new(
            key=transform_des_key(input_key=des_base[:7]),
            mode=DES.MODE_ECB
        ).encrypt(plaintext=server_challenge),
        DES.new(
            key=transform_des_key(input_key=des_base[7:14]),
            mode=DES.MODE_ECB
        ).encrypt(plaintext=server_challenge),
        DES.new(
            key=transform_des_key(input_key=des_base[14:21]),
            mode=DES.MODE_ECB
        ).encrypt(plaintext=server_challenge)
    ))


def produce_lm_response(lm_hash: bytes, server_challenge: bytes) -> bytes:
    return _produce_lm_or_ntlm_response(hash_bytes=lm_hash, server_challenge=server_challenge)


def produce_nt_response(nt_hash: bytes, server_challenge: bytes) -> bytes:
    return _produce_lm_or_ntlm_response(hash_bytes=nt_hash, server_challenge=server_challenge)


def produce_lm_and_ntlm_response(
    authentication_secret: Union[str, bytes],
    server_challenge: bytes
) -> Tuple[bytes, bytes]:
    """

    :param authentication_secret: Either a password or a NT hash, differentiated by type.
    :param server_challenge:
    :return:
    """
    if isinstance(authentication_secret, str):
        try:
            lm_hash = compute_lm_hash(input_bytes=authentication_secret.upper().encode(encoding='ascii'))
        except ValueError:
            lm_hash = bytes(16)

        nt_hash = compute_nt_hash(authentication_secret.encode(encoding='utf-16-le'))
    elif isinstance(authentication_secret, bytes):
        lm_hash = bytes(16)
        nt_hash = authentication_secret
    else:
        # TODO: Use proper exception.
        raise ValueError

    return (
        produce_lm_response(lm_hash=lm_hash, server_challenge=server_challenge),
        produce_nt_response(nt_hash=nt_hash, server_challenge=server_challenge)
    )


def produce_lmv2_and_ntlmv2_response(
    response_key_nt: bytes,
    response_key_lm: bytes,
    server_challenge: bytes,
    server_name: AVPairSequence,
    client_challenge: Optional[bytes] = None,
    time: Optional[bytes] = None
):
    nt_challenge_response, lm_challenge_response, session_base_key = compute_response(
        response_key_nt=response_key_nt,
        response_key_lm=response_key_lm,
        server_challenge=server_challenge,
        server_name=server_name,
        client_challenge=client_challenge,
        time=time
    )

    # "This structure is always sent in the CHALLENGE_MESSAGE.", meaning this check is redundant.
    # (maybe I want it anyway)
    # if challenge_message.target_information.timestamp:
    lm_challenge_response = bytes(24)

    return nt_challenge_response, lm_challenge_response, session_base_key


def ntow_v2_from_nt_hash(nt_hash: bytes, user: str, domain: str) -> bytes:
    return hmac_new(
        key=nt_hash,
        msg=(user.upper() + domain).encode(encoding='utf-16-le'),
        digestmod=hashlib_md5
    ).digest()


def lmowf_v2_from_nt_hash(nt_hash: bytes, user: str, domain: str) -> bytes:
    return ntow_v2_from_nt_hash(nt_hash=nt_hash, user=user, domain=domain)


def ntowf_v1(input_bytes: bytes) -> bytes:
    return compute_nt_hash(input_bytes=input_bytes)


def ntowf_v2(password: str, user: str, domain: str) -> bytes:
    return ntow_v2_from_nt_hash(
        nt_hash=compute_nt_hash(input_bytes=password.encode(encoding='utf-16-le')),
        user=user,
        domain=domain
    )


def lmowf_v1(input_bytes: bytes) -> bytes:
    return compute_lm_hash(input_bytes=input_bytes)


def lmowf_v2(password: str, user: str, domain: str) -> bytes:
    return ntowf_v2(password=password, user=user, domain=domain)