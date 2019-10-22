from typing import Optional, Union
from ipaddress import IPv4Address, IPv6Address
from copy import deepcopy
from secrets import token_bytes

from .messages.negotiate import NegotiateMessage
from .messages.challenge import ChallengeMessage
from .messages.authenticate import AuthenticateMessage
from .operations import produce_lm_and_ntlm_response, produce_lmv2_and_ntlmv2_response, lmowf_v2, ntowf_v2
from .structures.av_pair import TimestampAVPair
from .structures.negotiate_flags import NegotiateFlags

from Crypto.Cipher import ARC4


def ntlm_context(
    username: str,
    authentication_secret: Union[str, bytes],
    lm_compatibility_level: int = 3,
    domain_name: str = 'WORKSTATION',
    workstation_name: Optional[Union[str, IPv4Address, IPv6Address]] = None
):
    if lm_compatibility_level == 0:
        negotiate_message: NegotiateMessage = NegotiateMessage.make_ntlm_v1_negotiate()
        yield negotiate_message
    elif lm_compatibility_level == 1:
        raise NotImplementedError
    elif lm_compatibility_level == 2:
        raise NotImplementedError
    elif 3 <= lm_compatibility_level <= 5:
        negotiate_message: NegotiateMessage = NegotiateMessage.make_ntlm_v2_negotiate()
        yield negotiate_message
    else:
        # TODO: Use proper exception.
        raise ValueError

    challenge_message: ChallengeMessage = yield

    if lm_compatibility_level == 0:
        lm_challenge_response, nt_challenge_response = produce_lm_and_ntlm_response(
            authentication_secret=authentication_secret,
            server_challenge=challenge_message.challenge
        )
        encrypted_random_session_key = b''
    elif lm_compatibility_level == 1:
        raise NotImplementedError
    elif lm_compatibility_level == 2:
        raise NotImplementedError
    elif 3 <= lm_compatibility_level <= 5:
        server_name = deepcopy(challenge_message.target_info)

        # flags_av_pair: Optional[FlagsAVPair] = next(
        #     (av_pair for av_pair in server_name if isinstance(av_pair, FlagsAVPair)),
        #     None
        # )
        # if not flags_av_pair:
        #     flags_av_pair = FlagsAVPair(flags=AvFlags())
        #     server_name.add_av_pair(av_pair=flags_av_pair)
        #
        # flags_av_pair.flags.use_mic = True

        nt_challenge_response, lm_challenge_response, session_base_key = produce_lmv2_and_ntlmv2_response(
            response_key_nt=ntowf_v2(password=authentication_secret, user=username, domain=domain_name),
            response_key_lm=lmowf_v2(password=authentication_secret, user=username, domain=domain_name),
            server_challenge=challenge_message.challenge,
            server_name=server_name,
            time=next(
                av_pair
                for av_pair in challenge_message.target_info
                if isinstance(av_pair, TimestampAVPair)
            ).filetime
        )

        "If NTLM v2 is used, KeyExchangeKey MUST be set to the given 128-bit SessionBaseKey value."
        key_exchange_key: bytes = session_base_key
        if challenge_message.negotiate_flags.negotiate_key_exch:
            exported_session_key = token_bytes(nbytes=16)
            encrypted_random_session_key = ARC4.new(key=key_exchange_key).encrypt(plaintext=exported_session_key)
        else:
            exported_session_key = key_exchange_key
            encrypted_random_session_key = b''
    else:
        # TODO: Use proper exception.
        raise ValueError

    authenticate_message = AuthenticateMessage(
        lm_challenge_response=lm_challenge_response,
        nt_challenge_response=nt_challenge_response,
        domain_name=domain_name,
        user_name=username,
        workstation_name=str(workstation_name) if workstation_name is not None else None,
        encrypted_random_session_key=encrypted_random_session_key,
        os_version=None,
        negotiate_flags=NegotiateFlags(
            negotiate_always_sign=True,
            negotiate_ntlm=True,
            negotiate_unicode=True,
            negotiate_key_exch=True,
            request_target=True,
            negotiate_oem_domain_supplied=True,
            negotiate_oem_workstation_supplied=workstation_name is not None,
        ),
        mic=None
    )

    # if authentication_method is SessionSetupAuthenticationMethod.LM_NTLM_v2:
    #     authenticate_message.mic = 16 * b'\x00'
    #     mic: bytes = hmac_new(
    #         key=exported_session_key,
    #         msg=negotiate_message_bytes+challenge_message_bytes+bytes(authenticate_message)
    #     ).digest()
    #     authenticate_message.mic = mic
    #

    yield authenticate_message
