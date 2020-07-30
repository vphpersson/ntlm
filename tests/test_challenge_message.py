from ntlm.messages.challenge import ChallengeMessage
from ntlm.structures.negotiate_flags import NegotiateFlags
from ntlm.structures.av_pair_sequence import AVPairSequence
from ntlm.structures.version import Version


class TestChallengeMessage:
    CHALLENGE_MESSAGE = ChallengeMessage.from_bytes(
        buffer=bytes.fromhex('4e544c4d53535000020000000c000c003800000033828ae20123456789abcdef00000000000000002400240044000000060070170000000f53006500720076006500720002000c0044006f006d00610069006e0001000c0053006500720076006500720000000000')
    )

    def test_target_name(self, challenge_message: ChallengeMessage = CHALLENGE_MESSAGE):
        assert challenge_message.target_name == 'Server'

    def test_negotiate_flags(self, challenge_message: ChallengeMessage = CHALLENGE_MESSAGE):
        assert challenge_message.negotiate_flags.items() == NegotiateFlags.from_int(value=3800728115).items()

    def test_server_challenge(self, challenge_message: ChallengeMessage = CHALLENGE_MESSAGE):
        assert challenge_message.challenge == b'\x01#Eg\x89\xab\xcd\xef'

    def test_target_info(self, challenge_message: ChallengeMessage = CHALLENGE_MESSAGE):
        assert challenge_message.target_info == AVPairSequence.from_bytes(
            buffer=b'\x02\x00\x0c\x00D\x00o\x00m\x00a\x00i\x00n\x00\x01\x00\x0c\x00S\x00e\x00r\x00v\x00e\x00r\x00\x00\x00\x00\x00'
        )

    def test_os_version(self, challenge_message: ChallengeMessage = CHALLENGE_MESSAGE):
        assert challenge_message.os_version == Version.from_bytes(
            buffer=b'\x06\x00p\x17\x00\x00\x00\x0f'
        )

    def test_redeserialization(self):
        challenge_message = ChallengeMessage.from_bytes(buffer=bytes(self.CHALLENGE_MESSAGE))
        self.test_target_name(challenge_message=challenge_message)
        self.test_negotiate_flags(challenge_message=challenge_message)
        self.test_server_challenge(challenge_message=challenge_message)
        self.test_target_info(challenge_message=challenge_message)
        self.test_os_version(challenge_message=challenge_message)




