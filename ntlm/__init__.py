from typing import Union, Optional, Generator, ByteString
from copy import deepcopy
from secrets import token_bytes

from ntlm.messages.negotiate import NegotiateMessage
from ntlm.messages.challenge import ChallengeMessage
from ntlm.messages.authenticate import AuthenticateMessage
from ntlm.structures.negotiate_flags import NegotiateFlags
from ntlm.structures.av_pair_sequence import AVPairSequence
from ntlm.structures.av_pairs.timestamp import TimestampAVPair
from ntlm.structures.av_pairs.target_name import TargetNameAVPair
from ntlm.structures.av_pairs.flags import FlagsAVPair, AvFlags
from ntlm.structures.ntlmssp_message_signature import NTLMSSPMessageSignature
from ntlm.structures.version import Version
from ntlm.structures.ntlmv2_response import NTLMv2Response
from ntlm.operations.authentication import produce_lm_and_ntlm_response, produce_lmv2_and_ntlmv2_response, lmowf_v2, ntowf_v2, \
    ntow_v2_from_nt_hash, lmowf_v2_from_nt_hash
from ntlm.operations.session_security import make_sign_key, make_seal_key, Mode, sign, \
    calculate_authenticate_message_mic

from Crypto.Cipher import ARC4


class NTLMContext:

    def __init__(
        self,
        username: str,
        authentication_secret: Union[str, bytes],
        domain_name: str = '',
        workstation_name: str = '',
        version: Version = Version(),
        lm_compatibility_level: int = 3
    ):
        self.user: str = username
        self.user_dom: str = domain_name
        self.authentication_secret: Union[str, bytes] = authentication_secret
        self.workstation_name: str = workstation_name
        self.version: Version = version
        self.lm_compatibility_level = lm_compatibility_level

        self.neg_flg: Optional[NegotiateFlags] = None

        self.client_signing_key: Optional[bytes] = None
        self.client_sealing_key: Optional[bytes] = None
        self.sequence_number: int = 0
        self.server_signing_key: Optional[bytes] = None
        self.server_sealing_key: Optional[bytes] = None

        self.rc4_handle_client: Optional[ARC4] = None
        self.rc4_handle_server: Optional[ARC4] = None

    def _make_keys_and_cipher_handles(self, exported_session_key: bytes):
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

    def _make_authenticate_message(
        self,
        lm_challenge_response: bytes,
        nt_challenge_response: NTLMv2Response,
        encrypted_random_session_key: bytes,
        negotiate_message: Union[ByteString, NegotiateMessage],
        challenge_message: Union[ByteString, ChallengeMessage],
        exported_session_key: ByteString
    ) -> AuthenticateMessage:
        authenticate_message = AuthenticateMessage(
            lm_challenge_response=lm_challenge_response,
            nt_challenge_response=nt_challenge_response,
            domain_name=self.user_dom,
            user_name=self.user,
            workstation_name=self.workstation_name,
            encrypted_random_session_key=encrypted_random_session_key,
            negotiate_flags=self.neg_flg,
            os_version=self.version
        )

        authenticate_message.mic = calculate_authenticate_message_mic(
            negotiate_message=negotiate_message,
            challenge_message=challenge_message,
            authenticate_message=authenticate_message,
            exported_session_key=exported_session_key
        )

        return authenticate_message

    def _produce_response_key_nt(self) -> bytes:
        if isinstance(self.authentication_secret, str):
            return ntowf_v2(password=self.authentication_secret, user=self.user, domain=self.user_dom)
        else:
            return ntow_v2_from_nt_hash(nt_hash=self.authentication_secret, user=self.user, domain=self.user_dom)

    def _produce_response_key_lm(self) -> bytes:
        if isinstance(self.authentication_secret, str):
            return lmowf_v2(password=self.authentication_secret, user=self.user, domain=self.user_dom)
        else:
            return lmowf_v2_from_nt_hash(nt_hash=self.authentication_secret, user=self.user, domain=self.user_dom)

    @staticmethod
    def _make_server_name(challenge_message_target_info: AVPairSequence) -> AVPairSequence:

        server_name = challenge_message_target_info

        # Set the `FlagsAVPair` flag value to include `use_mic`. Add a `FlagsAVPair` if one does not already exist.

        flags_av_pair: Optional[FlagsAVPair] = next(
            (av_pair for av_pair in server_name if isinstance(av_pair, FlagsAVPair)),
            None
        )
        if not flags_av_pair:
            flags_av_pair = FlagsAVPair(flags=AvFlags())
            server_name.add_av_pair(av_pair=flags_av_pair)

        flags_av_pair.flags.use_mic = True

        return server_name

    def initiate(
        self,
        negotiate_message: Optional[NegotiateMessage] = None
    ) -> Generator[Union[NegotiateMessage, AuthenticateMessage], ChallengeMessage, None]:
        """
        Initiate an NTLM authentication procedure.

        :param negotiate_message: An NTLM negotiate message that will be used instead of a defaultly-constructed one.
        :return: An NTLM authenticate message.
        """

        if not (3 <= self.lm_compatibility_level <= 5):
            raise NotImplementedError

        negotiate_message: NegotiateMessage = negotiate_message or NegotiateMessage(
            negotiate_flags=NegotiateFlags(
                negotiate_unicode=True,
                request_target=True,
                negotiate_sign=True,
                negotiate_seal=True,
                negotiate_ntlm=True,
                negotiate_always_sign=True,
                negotiate_extended_sessionsecurity=True,
                negotiate_128=True,
                negotiate_key_exch=True,
                negotiate_56=True
            )
        )

        challenge_message: ChallengeMessage = yield negotiate_message

        self.neg_flg: NegotiateFlags = challenge_message.negotiate_flags

        nt_challenge_response, lm_challenge_response, session_base_key = produce_lmv2_and_ntlmv2_response(
            response_key_nt=self._produce_response_key_nt(),
            response_key_lm=self._produce_response_key_lm(),
            server_challenge=challenge_message.challenge,
            # NOTE: I have `target_info` as optional in `ChallengeMessage`...
            server_name=self._make_server_name(
                challenge_message_target_info=deepcopy(challenge_message.target_info)
            ),
            time=next(
                av_pair
                for av_pair in challenge_message.target_info
                if isinstance(av_pair, TimestampAVPair)
            ).filetime
        )

        key_exchange_key: bytes = session_base_key

        if challenge_message.negotiate_flags.negotiate_key_exch:
            exported_session_key: bytes = token_bytes(nbytes=16)
            encrypted_random_session_key: bytes = ARC4.new(
                key=key_exchange_key
            ).encrypt(plaintext=exported_session_key)
        else:
            exported_session_key: bytes = key_exchange_key
            encrypted_random_session_key: bytes = b''

        self._make_keys_and_cipher_handles(exported_session_key=exported_session_key)

        yield self._make_authenticate_message(
            lm_challenge_response=lm_challenge_response,
            nt_challenge_response=nt_challenge_response,
            encrypted_random_session_key=encrypted_random_session_key,
            negotiate_message=negotiate_message,
            challenge_message=challenge_message,
            exported_session_key=exported_session_key
        )

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
