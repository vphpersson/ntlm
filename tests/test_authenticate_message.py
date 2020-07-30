from ntlm.messages.authenticate import AuthenticateMessage
from ntlm.structures.negotiate_flags import NegotiateFlags
from ntlm.structures.ntlmv2_response import NTLMv2Response
from ntlm.structures.version import Version


class TestAuthenticateMessage:
    AUTHENTICATE_MESSAGE = AuthenticateMessage.from_bytes(
        buffer=bytes.fromhex('4e544c4d5353500003000000180018006c00000054005400840000000c000c00480000000800080054000000100010005c00000010001000d8000000358288e20501280a0000000f44006f006d00610069006e00550073006500720043004f004d005000550054004500520086c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa68cd0ab851e51c96aabc927bebef6a1c01010000000000000000000000000000aaaaaaaaaaaaaaaa0000000002000c0044006f006d00610069006e0001000c005300650072007600650072000000000000000000c5dad2544fc9799094ce1ce90bc9d03e')
    )

    def test_lm_challenge_response(self, authentication_message: AuthenticateMessage = AUTHENTICATE_MESSAGE):
        assert authentication_message.lm_challenge_response == b'\x86\xc3P\x97\xac\x9c\xec\x10%TvJW\xcc\xcc\x19\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'

    def test_nt_challenge_response(self, authentication_message: AuthenticateMessage = AUTHENTICATE_MESSAGE):
        assert authentication_message.nt_challenge_response == NTLMv2Response.from_bytes(
            buffer=b'h\xcd\n\xb8Q\xe5\x1c\x96\xaa\xbc\x92{\xeb\xefj\x1c\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x00\x00\x00\x00\x02\x00\x0c\x00D\x00o\x00m\x00a\x00i\x00n\x00\x01\x00\x0c\x00S\x00e\x00r\x00v\x00e\x00r\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        )

    def test_domain_name(self, authentication_message: AuthenticateMessage = AUTHENTICATE_MESSAGE):
        assert authentication_message.domain_name == 'Domain'

    def test_user_name(self, authentication_message: AuthenticateMessage = AUTHENTICATE_MESSAGE):
        assert authentication_message.user_name == 'User'

    def test_workstation_name(self, authentication_message: AuthenticateMessage = AUTHENTICATE_MESSAGE):
        assert authentication_message.workstation_name == 'COMPUTER'

    def test_negotiate_flags(self, authentication_message: AuthenticateMessage = AUTHENTICATE_MESSAGE):
        assert authentication_message.negotiate_flags.items() == NegotiateFlags.from_int(value=3800597045).items()

    def test_encrypted_random_session_key(self, authentication_message: AuthenticateMessage = AUTHENTICATE_MESSAGE):
        assert authentication_message.encrypted_random_session_key == b'\xc5\xda\xd2TO\xc9y\x90\x94\xce\x1c\xe9\x0b\xc9\xd0>'

    def test_os_version(self, authentication_message: AuthenticateMessage = AUTHENTICATE_MESSAGE):
        assert authentication_message.os_version == Version.from_bytes(buffer=b'\x05\x01(\n\x00\x00\x00\x0f')

    def test_mic(self, authentication_message: AuthenticateMessage = AUTHENTICATE_MESSAGE):
        assert authentication_message.mic == b'D\x00o\x00m\x00a\x00i\x00n\x00U\x00s\x00'

    def test_redeserialization(self):
        authentication_message = AuthenticateMessage.from_bytes(buffer=bytes(self.AUTHENTICATE_MESSAGE))
        self.test_lm_challenge_response(authentication_message=authentication_message)
        self.test_nt_challenge_response(authentication_message=authentication_message)
        self.test_domain_name(authentication_message=authentication_message)
        self.test_user_name(authentication_message=authentication_message)
        self.test_workstation_name(authentication_message=authentication_message)
        self.test_negotiate_flags(authentication_message=authentication_message)
        self.test_encrypted_random_session_key(authentication_message=authentication_message)
        self.test_os_version(authentication_message=authentication_message)
        self.test_mic(authentication_message=authentication_message)

