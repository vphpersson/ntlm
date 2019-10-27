from enum import IntFlag

from msdsalgs.utils import make_mask_class


class NegotiateFlagsMask(IntFlag):
    NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
    NTLMSSP_NEGOTIATE_OEM = 0x00000002
    NTLMSSP_REQUEST_TARGET = 0x00000004
    NTLMSSP_NEGOTIATE_SIGN = 0x00000010
    NTLMSSP_NEGOTIATE_SEAL = 0x00000020
    NTLMSSP_NEGOTIATE_DATAGRAM = 0x00000040
    NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080
    NTLMSSP_NEGOTIATE_NTLM = 0x00000200
    # This capability does not have an alternate name.
    ANONYMOUS = 0x00000800
    NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000
    NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
    NTLMSSP_TARGET_TYPE_DOMAIN = 0x00010000
    NTLMSSP_TARGET_TYPE_SERVER = 0x00020000
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
    NTLMSSP_NEGOTIATE_IDENTIFY = 0x00100000
    NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 0x00400000
    NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
    NTLMSSP_NEGOTIATE_VERSION = 0x02000000
    NTLMSSP_NEGOTIATE_128 = 0x20000000
    NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
    NTLMSSP_NEGOTIATE_56 = 0x80000000


NegotiateFlags = make_mask_class(NegotiateFlagsMask, prefix='NTLMSSP_')
