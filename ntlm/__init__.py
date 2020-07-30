from typing import Union, Optional, Generator
from copy import deepcopy
from secrets import token_bytes
from hmac import new as hmac_new

from ntlm.messages.negotiate import NegotiateMessage
from ntlm.messages.challenge import ChallengeMessage
from ntlm.messages.authenticate import AuthenticateMessage
from ntlm.structures.negotiate_flags import NegotiateFlags
from ntlm.operations.authentication import produce_lm_and_ntlm_response, produce_lmv2_and_ntlmv2_response, lmowf_v2, ntowf_v2, \
    ntow_v2_from_nt_hash, lmowf_v2_from_nt_hash
from ntlm.structures.av_pairs.timestamp import TimestampAVPair
from ntlm.structures.av_pairs.target_name import TargetNameAVPair
from ntlm.structures.av_pairs.flags import FlagsAVPair, AvFlags
from ntlm.operations.session_security import make_sign_key, make_seal_key, Mode, sign
from ntlm.structures.ntlmssp_message_signature import NTLMSSPMessageSignature

from Crypto.Cipher import ARC4


class NTLMContext:

    def __init__(
        self,
        username: str,
        authentication_secret: Union[str, bytes],
        domain_name: str = '',
        lm_compatibility_level: int = 3,
        workstation_name: str = ''
    ):
        self.user: str = username
        self.user_dom: str = domain_name
        self.authentication_secret: Union[str, bytes] = authentication_secret

        self.workstation_name: Optional[str] = workstation_name

        self.lm_compatibility_level = lm_compatibility_level

        self.neg_flg: Optional[NegotiateFlags] = None

        self.client_signing_key: Optional[bytes] = None
        self.client_sealing_key: Optional[bytes] = None
        self.sequence_number: int = 0
        self.server_signing_key: Optional[bytes] = None
        self.server_sealing_key: Optional[bytes] = None

        self.rc4_handle_client: Optional[ARC4] = None
        self.rc4_handle_server: Optional[ARC4] = None

    def initiate(
        self,
        negotiate_message: Optional[NegotiateMessage] = None
    ) -> Generator[Union[NegotiateMessage, AuthenticateMessage], ChallengeMessage, None]:
        """
        Initiate an NTLM authentication procedure.

        :param negotiate_message: An NTLM negotiate message that will be used instead of a defaultly-constructed one.
        :return: An NTLM authenticate message.
        """

        if negotiate_message is None:
            if self.lm_compatibility_level == 0:
                negotiate_message: NegotiateMessage = NegotiateMessage.make_ntlm_v1_negotiate()
            elif self.lm_compatibility_level == 1:
                raise NotImplementedError
            elif self.lm_compatibility_level == 2:
                raise NotImplementedError
            elif 3 <= self.lm_compatibility_level <= 5:
                negotiate_message: NegotiateMessage = NegotiateMessage.make_ntlm_v2_negotiate()
            else:
                # TODO: Use proper exception.
                raise ValueError

        challenge_message = yield negotiate_message

        if self.lm_compatibility_level == 0:
            lm_challenge_response, nt_challenge_response = produce_lm_and_ntlm_response(
                authentication_secret=self.authentication_secret,
                server_challenge=challenge_message.challenge
            )
            encrypted_random_session_key = b''
        elif self.lm_compatibility_level == 1:
            raise NotImplementedError
        elif self.lm_compatibility_level == 2:
            raise NotImplementedError
        elif 3 <= self.lm_compatibility_level <= 5:
            server_name = deepcopy(challenge_message.target_info)
            # TODO: Why empty? Could it be not empty?
            server_name.add_av_pair(av_pair=TargetNameAVPair(target_name=''))

            flags_av_pair: Optional[FlagsAVPair] = next(
                (av_pair for av_pair in server_name if isinstance(av_pair, FlagsAVPair)),
                None
            )
            if not flags_av_pair:
                flags_av_pair = FlagsAVPair(flags=AvFlags())
                server_name.add_av_pair(av_pair=flags_av_pair)

            flags_av_pair.flags.use_mic = True

            # TODO: Clean this up!!
            nt_challenge_response, lm_challenge_response, session_base_key = produce_lmv2_and_ntlmv2_response(
                response_key_nt=(
                    ntowf_v2(password=self.authentication_secret, user=self.user, domain=self.user_dom)
                    if isinstance(self.authentication_secret, str)
                    else ntow_v2_from_nt_hash(nt_hash=self.authentication_secret, user=self.user, domain=self.user_dom)
                ),
                response_key_lm=(
                    lmowf_v2(password=self.authentication_secret, user=self.user, domain=self.user_dom)
                    if isinstance(self.authentication_secret, str)
                    else lmowf_v2_from_nt_hash(nt_hash=self.authentication_secret, user=self.user, domain=self.user_dom)
                ),
                server_challenge=challenge_message.challenge,
                server_name=server_name,
                time=next(
                    av_pair
                    for av_pair in challenge_message.target_info
                    if isinstance(av_pair, TimestampAVPair)
                ).filetime
            )

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

        # TODO: I think the flags should be the same as received in the challenge message.

        authenticate_message = AuthenticateMessage(
            lm_challenge_response=lm_challenge_response,
            nt_challenge_response=nt_challenge_response,
            domain_name=self.user_dom,
            user_name=self.user,
            # TODO: This is not right.
            workstation_name=str(self.workstation_name) if self.workstation_name is not None else None,
            encrypted_random_session_key=encrypted_random_session_key,
            os_version=None,
            negotiate_flags=NegotiateFlags(
                negotiate_128=True,
                negotiate_56=True,
                negotiate_always_sign=True,
                negotiate_extended_sessionsecurity=True,
                negotiate_key_exch=True,
                negotiate_ntlm=True,
                negotiate_seal=True,
                negotiate_sign=True,
                negotiate_unicode=True,
                # TODO: This is not right.
                negotiate_oem_domain_supplied=self.user_dom is not None,
                negotiate_oem_workstation_supplied=self.workstation_name is not None,
            ),
            mic=None
        )

        if 3 <= self.lm_compatibility_level <= 5:
            authenticate_message.mic = bytes(16)
            mic: bytes = hmac_new(
                key=exported_session_key,
                msg=bytes(negotiate_message) + bytes(challenge_message) + bytes(authenticate_message),
                digestmod='md5'
            ).digest()
            authenticate_message.mic = mic

        self.neg_flg: NegotiateFlags = authenticate_message.negotiate_flags

        self.client_signing_key: bytes = make_sign_key(
            negotiate_flags=self.neg_flg,
            exported_session_key=exported_session_key,
            mode=Mode.CLIENT
        )

        self.server_signing_key: bytes = make_sign_key(
            negotiate_flags=self.neg_flg,
            exported_session_key=exported_session_key,
            mode=Mode.SERVER
        )

        self.client_sealing_key: bytes = make_seal_key(
            negotiate_flags=self.neg_flg,
            exported_session_key=exported_session_key,
            mode=Mode.CLIENT
        )

        self.server_sealing_key: bytes = make_seal_key(
            negotiate_flags=self.neg_flg,
            exported_session_key=exported_session_key,
            mode=Mode.SERVER
        )

        self.rc4_handle_client: ARC4 = ARC4.new(key=self.client_sealing_key)
        self.rc4_handle_server: ARC4 = ARC4.new(key=self.server_sealing_key)

        yield authenticate_message

    def sign(self, data: bytes, as_bytes: bool = False) -> Union[NTLMSSPMessageSignature, bytes]:
        signature: NTLMSSPMessageSignature = sign(
            cipher_handle=self.rc4_handle_client,
            signing_key=self.client_signing_key,
            data=data,
            sequence_number=self.sequence_number,
            negotiate_flags=self.neg_flg
        )
        self.sequence_number += 1

        return bytes(signature) if as_bytes else signature

    def verify_signature(self):
        # TODO: Implement.
        ...
