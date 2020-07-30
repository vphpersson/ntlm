from ntlm.messages.negotiate import NegotiateMessage
from ntlm.structures.negotiate_flags import NegotiateFlags
from ntlm.structures.version import Version


class TestNegotiateMessage:
    NEGOTIATE_MESSAGE = NegotiateMessage.from_bytes(
        buffer=bytes.fromhex('4e544c4d5353500001000000978208e2000000000000000000000000000000000a0063450000000f')
    )

    def test_negotiate_flags(self, negotiate_message: NegotiateMessage = NEGOTIATE_MESSAGE):
        assert negotiate_message.negotiate_flags.items() == NegotiateFlags.from_int(value=0xe2088297).items()

    def test_domain_name(self, negotiate_message: NegotiateMessage = NEGOTIATE_MESSAGE):
        assert negotiate_message.domain_name == ''

    def test_workstation_name(self, negotiate_message: NegotiateMessage = NEGOTIATE_MESSAGE):
        assert negotiate_message.workstation_name == ''

    def test_os_version(self, negotiate_message: NegotiateMessage = NEGOTIATE_MESSAGE):
        assert negotiate_message.os_version == Version(
            major_version_number=10,
            minor_version_number=0,
            build_number=17763
        )

    def test_redeserialization(self):
        negotiate_message = NegotiateMessage.from_bytes(buffer=bytes(self.NEGOTIATE_MESSAGE))
        self.test_negotiate_flags(negotiate_message=negotiate_message)
        self.test_domain_name(negotiate_message=negotiate_message)
        self.test_workstation_name(negotiate_message=negotiate_message)
        self.test_os_version(negotiate_message=negotiate_message)
