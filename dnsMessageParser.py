"""
DNS Message Parser
2024 Marcel Schmalzl
"""
# Enter your code here. Read input from STDIN. Print output to STDOUT
# RFCs:
# * [Domain Names – Concepts and Facilities](https://datatracker.ietf.org/doc/html/rfc1035)
# * [Domain Names – Implementation and Specification](https://datatracker.ietf.org/doc/html/rfc1034)
# * [DNS Extensions to Support IP Version 6](https://datatracker.ietf.org/doc/html/rfc3596)

from ctypes import BigEndianStructure, c_uint16, c_uint8, sizeof
import ipaddress
from dataclasses import dataclass


BYTE = 1


class DnsMsgHeader(BigEndianStructure):   # Network Byte order: Big Endian (https://twu.seanho.com/09spr/cmpt166/lectures/29-dns.pdf, slide 7)
    """
    DNS message header object
    """
    _pack_ = 1          # To avoid padding
    # Bit field definitions; must have same type to avoid padding (or use `_pack_ = 1`); we must choose c_uint16 (no negative numbers; biggest field is 16 bit)
    _fields_ = [
        ("ID", c_uint16, 16),        # Identifier assigned by the program that generates any kind of query
        ("QR", c_uint8, 1),
        ("OPCODE", c_uint8, 4),      # 0: standard query (QUERY), 1: inverse query (IQUERY), 2: server status request (STATUS), 3-15: reserved for future use
        ("AA", c_uint8, 1),          # Authoritative Answer: NS is an authority for domain name in question
        ("TC", c_uint8, 1),          # TrunCation (if is truncated due to length greater than permitted by transmission channel)
        ("RD", c_uint8, 1),          # Recursion Desired?
        ("RA", c_uint8, 1),          # Recursion avail?
        ("Z", c_uint8, 3),           # Always 0 (future use)
        ("RCODE", c_uint8, 4),       # Response code (* error, no error, ...)
        ("QDCOUNT", c_uint16, 16),   # Num. of entries in question section
        ("ANCOUNT", c_uint16, 16),   # Num. of entries in answer section
        ("NSCOUNT", c_uint16, 16),   # Num. of NS resource records (RR) in auth. records section
        ("ARCOUNT", c_uint16, 16),   # Num. of RR in add. records section
    ]

    opCodeLUT = {
        0: "QUERY",
        1: "IQUERY",
        2: "STATUS",
        3: "RESERVED",
        4: "RESERVED",
        5: "RESERVED",
        6: "RESERVED",
        7: "RESERVED",
        8: "RESERVED",
        9: "RESERVED",
        10: "RESERVED",
        11: "RESERVED",
        12: "RESERVED",
        13: "RESERVED",
        14: "RESERVED",
        15: "RESERVED",
    }

    rCodeLUT = {        # = status
        0: "NOERROR",
        1: "Format error",
        2: "Server failure",
        3: "Name Error",
        4: "Not Implemented",
        5: "Refused ",
        6: "RESERVED",
        7: "RESERVED",
        8: "RESERVED",
        9: "RESERVED",
        10: "RESERVED",
        11: "RESERVED",
        12: "RESERVED",
        13: "RESERVED",
        14: "RESERVED",
        15: "RESERVED",
    }

    COMMENT_PREFIX = ";; "

    def _sanityChecks(self) -> None:
        """
        Runs some sanity check on the input data stream
        :return: None
        """
        if self.fields.Z != 0:
            msg = f"The header Z value must always be zero but is: {self.fields.Z}"
            raise ValueError(msg)

    def __init__(self, inputHexBytes: bytes) -> None:
        """
        Initialises DNS header object
        :param inputHexBytes: Input binary hex datastream
        """
        super().__init__()
        self._headerBytes = inputHexBytes[:sizeof(DnsMsgHeader)]
        self.fields = DnsMsgHeader.from_buffer_copy(self._headerBytes)
        self._sanityChecks()

    def questionSecExists(self) -> bool:
        return self.fields.QDCOUNT > 0

    def answerSecExists(self) -> bool:
        return self.fields.ANCOUNT > 0

    def print(self) -> None:
        """
        Print the parsed header to stdout

        Example:
            Input binary hex stream: a01d81800001000100000000076578616d706c6503636f6d0000010001c00c0001000100001bbc00045db8d822
            Prints:
            ```
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40989
            ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

            ```
        :return: None
        """
        HEADER_PREFIX = "->>HEADER<<- "
        print(f"{self.COMMENT_PREFIX}{HEADER_PREFIX}opcode: {self.opCodeLUT.get(self.fields.OPCODE, 'INVALID')}, status: {self.rCodeLUT.get(self.fields.RCODE, 'INVALID')}, id: {self.fields.ID}")
        concatedFlagStr = " ".join(
            filter(None, [
                'qr' if self.fields.QR else None,
                'rd' if self.fields.RD else None,
                'ra' if self.fields.RA else None,
                'aa' if self.fields.AA else None
                ]
            )
        )
        print(f"{self.COMMENT_PREFIX}flags: {concatedFlagStr}; QUERY: {self.fields.QDCOUNT}, ANSWER: {self.fields.ANCOUNT}, AUTHORITY: {self.fields.NSCOUNT}, ADDITIONAL: {self.fields.ARCOUNT}")
        print()


class DnsMsgQA(BigEndianStructure):   # Network Byte order: Big Endian (https://twu.seanho.com/09spr/cmpt166/lectures/29-dns.pdf, slide 7)
    """
    DNS message question object
    We have this structure for each "question"/query -> QDCOUNT (usually 1)
    """

    COMMENT_PREFIX = ";; "

    @dataclass
    class QuestionSec:
        """
        Data struct for parsed question section data
        """
        qname: str          # = domain name
        qclass: int
        qtype: int

    classLUT = {  # Value description: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
        1: "IN",
        2: "CS",
        3: "CH",
        4: "HS",
    }

    # Qtype value description: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2 & https://en.wikipedia.org/wiki/List_of_DNS_record_types & https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
    qtypeLUT = {            # Source: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml (seems https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2 is not sufficient)
        0: "Reserved",
        1: "A",
        2: "NS",
        3: "MD",
        4: "MF",
        5: "CNAME",
        6: "SOA",
        7: "MB",
        8: "MG",
        9: "MR",
        10: "NULL",
        11: "WKS",
        12: "PTR",
        13: "HINFO",
        14: "MINFO",
        15: "MX",
        16: "TXT",
        17: "RP",
        18: "AFSDB",
        19: "X25",
        20: "ISDN",
        21: "RT",
        22: "NSAP",
        23: "NSAP-PTR",
        24: "SIG",
        25: "KEY",
        26: "PX",
        27: "GPOS",
        28: "AAAA",
        29: "LOC",
        30: "NXT",
        31: "EID",
        32: "NIMLOC",
        33: "SRV",
        34: "ATMA",
        35: "NAPTR",
        36: "KX",
        37: "CERT",
        38: "A6",
        39: "DNAME",
        40: "SINK",
        41: "OPT",
        42: "APL",
        43: "DS",
        44: "SSHFP",
        45: "IPSECKEY",
        46: "RRSIG",
        47: "NSEC",
        48: "DNSKEY",
        49: "DHCID",
        50: "NSEC3",
        51: "NSEC3PARAM",
        52: "TLSA",
        53: "SMIMEA",
        54: "Unassigned",
        55: "HIP",
        56: "NINFO",
        57: "RKEY",
        58: "TALINK",
        59: "CDS",
        60: "CDNSKEY",
        61: "OPENPGPKEY",
        62: "CSYNC",
        63: "ZONEMD",
        64: "SVCB",
        65: "HTTPS",
        # 66-98: "Unassigned",
        99: "SPF",
        100: "UINFO",
        101: "UID",
        102: "GID",
        103: "UNSPEC",
        104: "NID",
        105: "L32",
        106: "L64",
        107: "LP",
        108: "EUI48",
        109: "EUI64",
        # 110-248: "Unassigned",
        249: "TKEY",
        250: "TSIG",
        251: "IXFR",
        252: "AXFR",
        253: "MAILB",
        254: "MAILA",
        255: "*",
        256: "URI",
        257: "CAA",
        258: "AVC",
        259: "DOA",
        260: "AMTRELAY",
        261: "RESINFO",
        # 262-32767: "Unassigned",
        32768: "TA",
        32769: "DLV",
        # 32770-65279: "Unassigned",
        # 65280-65534: "Private use",
        65535: "Reserved",
    }

    class AnswerSec:
        """
        Data struct for parsed answer section data
        """
        @staticmethod
        def _unifyToInt(numToUnify: int | bytes) -> int:
            if type(numToUnify) is int:
                convertedNumToInt: int = numToUnify
            elif type(numToUnify) is bytes:
                convertedNumToInt: int = int.from_bytes(numToUnify, 'big')
            else:
                msg = f"Unsupported input type (must be int or bytes; got: `{type(numToUnify)}`)!"
                raise TypeError(msg)
            return convertedNumToInt

        def __init__(self, ansName: str, ansType: int | bytes, ansClass: int | bytes, ansTTL: int, rDLength: int | bytes, rData: str):
            self.ansName: str = ansName
            self.ansType: int = self._unifyToInt(ansType)
            self.ansClass: int = self._unifyToInt(ansClass)
            self.ansTTL: int = self._unifyToInt(ansTTL)
            self.rdLength: int = self._unifyToInt(rDLength)
            self.rData: str = rData

        def getClassLabel(self):
            return DnsMsgQA.classLUT.get(self.ansClass, 'INVALID')

        def getTypeLabel(self):
            return DnsMsgQA.qtypeLUT.get(self.ansClass, 'INVALID')

    def __init__(self):
        super().__init__()
        self.answerSecOffset: int = 0
        self.questionSecsOffset: int = 0
        self.questionEntries: list[DnsMsgQA.QuestionSec] = []
        self.answerEntries: list[DnsMsgQA.AnswerSec] = []

    def parseQuestion(self, header: DnsMsgHeader, binHexStrToDecode: bytes) -> int:
        """
        Parse the DNS question section and stores the individual values
        :param header: Header input object (needed for processing)
        :param binHexStrToDecode:
        :return:
        """
        questionSecsOffset = 0
        # Per question section
        for _ in range(header.fields.QDCOUNT):
            # QNAME = domain name
            domainName, questionSecsOffset = self.decodeDomainName(binHexStrToDecode=binHexStrToDecode, offset=sizeof(DnsMsgHeader))

            # QTYPE
            LEN_QTYPE = 2  # bytes
            qtypeEndPos = questionSecsOffset + LEN_QTYPE
            qtype = binHexStrToDecode[questionSecsOffset:qtypeEndPos]
            qtype = int.from_bytes(qtype, 'big')
            questionSecsOffset += LEN_QTYPE
            # print(f"qtype: `{qtype}` (= {DnsMsgQA.qtypeLUT[qtype})")         # Debug print

            # QCLASS
            LEN_QCLASS = 2  # bytes
            qclassEndPos = questionSecsOffset + LEN_QCLASS
            qclass = binHexStrToDecode[questionSecsOffset:qclassEndPos]
            qclass = int.from_bytes(qclass, 'big')
            questionSecsOffset += LEN_QCLASS
            # print(f"qclass: `{qclass}` (= {DnsMsgQA.classLUT[qclass]})")         # Debug print

            # Add to data struct
            self.questionEntries.append(self.QuestionSec(qname=domainName, qclass=qclass, qtype=qtype))
        self.questionSecsOffset = questionSecsOffset
        return questionSecsOffset

    def parseAnswer(self, header: DnsMsgHeader, binHexStrToDecode: bytes) -> int:
        HEADER_ANSWER = "ANSWER SECTION:"
        print(f"{self.COMMENT_PREFIX}{HEADER_ANSWER}")

        answerSecOffset = self.questionSecsOffset
        # Per answer section
        for _ in range(header.fields.ANCOUNT):
            domainNameAnsw, answerSecOffset = self.decodeDomainName(binHexStrToDecode=binHexStrToDecode, offset=answerSecOffset)

            ANS_TYPE_OFFSET = BYTE * 2
            ansType = binHexStrToDecode[answerSecOffset:answerSecOffset + ANS_TYPE_OFFSET]
            ansType = int.from_bytes(ansType, 'big')
            answerSecOffset += ANS_TYPE_OFFSET

            ANS_CLASS_OFFSET = BYTE * 2
            ansClass = binHexStrToDecode[answerSecOffset:answerSecOffset + ANS_CLASS_OFFSET]
            ansClass = int.from_bytes(ansClass, 'big')
            answerSecOffset += ANS_CLASS_OFFSET

            ANS_TTL_OFFSET = BYTE * 4
            ansTTL = binHexStrToDecode[answerSecOffset:answerSecOffset + ANS_TTL_OFFSET]
            ansTTL = int.from_bytes(ansTTL, 'big')
            answerSecOffset += ANS_TTL_OFFSET

            ANS_RDLENGTH_OFFSET = BYTE * 2
            rdLength = binHexStrToDecode[answerSecOffset:answerSecOffset + ANS_RDLENGTH_OFFSET]
            answerSecOffset += ANS_RDLENGTH_OFFSET
            rdLength = int.from_bytes(rdLength, 'big')

            # RDATA processing
            rData, answerSecOffset = DnsMsgQA.dispatchQTypeProc(
                qtype=self.qtypeLUT.get(ansType, 'INVALID'),            # Manually do the look-up because we don't have all data yet to construct the object
                qclass=self.classLUT.get(ansClass, 'INVALID'),          # Manually do the look-up because we don't have all data yet to construct the object
                payload=binHexStrToDecode,
                offset=answerSecOffset,
                rdLength=rdLength
            )

            # Add to data struct
            self.answerEntries.append(self.AnswerSec(ansName=domainNameAnsw, ansType=ansType, ansClass=ansClass, ansTTL=ansTTL, rDLength=rdLength, rData=rData))

        self.answerSecOffset = answerSecOffset
        return answerSecOffset

    def printQuestion(self):
        """
        Print the parsed question section to stdout

        Example:
            Input binary hex stream: a01d81800001000100000000076578616d706c6503636f6d0000010001c00c0001000100001bbc00045db8d822
            Prints:
            ```
            ;; QUESTION SECTION:
            ;example.com.		IN	A

            ```
        :return: None
        """
        HEADER_QUESTION = "QUESTION SECTION:"
        print(f"{self.COMMENT_PREFIX}{HEADER_QUESTION}")
        for qEntry in self.questionEntries:
            print(f";{qEntry.qname}\t\t{self.classLUT.get(qEntry.qclass, 'INVALID')}\t{self.qtypeLUT.get(qEntry.qtype, 'INVALID')}")
        print()

    def printAnswer(self):
        """
        Print the parsed answer section to stdout

        Example:
            Input binary hex stream: a01d81800001000100000000076578616d706c6503636f6d0000010001c00c0001000100001bbc00045db8d822
            Prints:
            ```
            ;; ANSWER SECTION:
            example.com.		7100	IN	A	93.184.216.34

            ```
        :return: None
        """
        for aEntry in self.answerEntries:
            print(f"{aEntry.ansName}\t\t{aEntry.ansTTL}\t{DnsMsgQA.classLUT.get(aEntry.ansClass, 'INVALID')}\t{DnsMsgQA.qtypeLUT.get(aEntry.ansType, 'INVALID')}\t{aEntry.rData}")

    @classmethod
    def dispatchQTypeProc(cls, qtype: str, qclass: str, payload: bytes, offset: int, rdLength: int) -> tuple[str, int]:
        """
        Dispatches to the correct processing function based on qtype and qclass
        :param qtype: DNS message qtype to decide on matching processor via LUT
        :param qclass: DNS message qclass to decide on matching processor via LUT (not yet used for decision-making)
        :param payload: Full message bytes string to decode
        :param offset: Start offset for decoding
        :param rdLength: Length of RD section to decode
        :return: Extracted string from processing and offset after processing
        """
        qtypeProcessor = cls._qtypeDispatchLUT.get(qtype, 'INVALID')
        if qtypeProcessor is not None:
            return qtypeProcessor(payload, offset, rdLength)
            # TODO: We could move the offset rdLength check as a generic sanity check here to make individual implementations easier (MSc)
        else:
            print(f"QType {qtype} not implemented for processing yet!")

    class _RDataProcessor:
        """
        Processing of RDATA types
        All functions need a:
        :param inByteStream: [bytes] Input bytes stream to process
        :param offsetOrig: [int] Offset used where to start processing in inByteStream
        :param rdLength: [int] rdLength (sometimes used for processing; we usually check against "logical" length (calculated offset based on spec) as sanity check)
        :return: [tuple[str, int]] processed string and resulting offset after processing
        """
        @staticmethod
        def ipv4(inByteStream: bytes, offsetOrig: int, rdLength: int) -> tuple[str, int]:
            """
            IPv4 processor
            """
            offsetLoc = offsetOrig
            ANS_IPv4_OFFSET = BYTE
            ips = []
            IPv4_PARTS = 4
            for ipv4part in range(0, IPv4_PARTS):
                ips.append(inByteStream[offsetLoc:offsetLoc+ANS_IPv4_OFFSET])
                offsetLoc += ANS_IPv4_OFFSET
            ips = list(map(lambda ip: str(int.from_bytes(ip, 'big')), ips))
            ip = ".".join(ips)
            offset = IPv4_PARTS * ANS_IPv4_OFFSET

            # Sanity check
            if offset != rdLength:
                msg = f"offset={offset} != rdLength={rdLength}! Input data may be invalid."
                raise ValueError(msg)
            return ip, offsetOrig+rdLength

        @staticmethod
        def ipv6(inByteStream: bytes, offsetOrig: int, rdLength: int) -> tuple[str, int]:
            """
            IPv6 processor
            Format and size: https://datatracker.ietf.org/doc/html/rfc3596#autoid-4

            The preferred form is x:x:x:x:x:x:x:x, where the 'x's are the
            hexadecimal values of the eight 16-bit pieces of the address.

            Examples:
            FEDC:BA98:7654:3210:FEDC:BA98:7654:3210
            1080:0:0:0:8:800:200C:417A
            """
            offset = offsetOrig
            ANS_IPv6_OFFSET = BYTE*2
            ips = []
            IPv6_PARTS = 8
            for ipv4part in range(0, IPv6_PARTS):
                partHex = inByteStream[offset:offset+ANS_IPv6_OFFSET].hex()
                ips.append(partHex if partHex != bytes(b'\x00\x00') else None)
                offset += ANS_IPv6_OFFSET
            ips = list(map(lambda ip: str(ip), filter(None, ips)))
            ip = ":".join(ips)
            ip = ipaddress.ip_address(ip).compressed            # Compression as in https://datatracker.ietf.org/doc/html/rfc3513#section-2.2
            offset = IPv6_PARTS * ANS_IPv6_OFFSET

            # Sanity check
            if offset != rdLength:
                msg = f"offset={offset} != rdLength={rdLength}! Input data may be invalid."
                raise ValueError(msg)
            return ip, offsetOrig+rdLength

        @staticmethod
        def cname(inByteStream: bytes, offsetOrig: int, rdLength: int) -> tuple[str, int]:
            """
            CNAME processor
            """
            cname, offsetTot = DnsMsgQA.decodeDomainName(binHexStrToDecode=inByteStream, offset=offsetOrig)
            offset = offsetTot - offsetOrig

            # Sanity check
            if offset != rdLength:
                msg = f"offset={offset} != rdLength={rdLength}! Input data may be invalid."
                raise ValueError(msg)
            return cname, offsetOrig+rdLength

    # LUT for processing function selection or RDATA sections
    _qtypeDispatchLUT = {
        "A": _RDataProcessor.ipv4,
        "AAAA": _RDataProcessor.ipv6,
        "CNAME": _RDataProcessor.cname,
    }

    @classmethod
    def decodeDomainName(cls, binHexStrToDecode: bytes, offset: int = 0) -> tuple[str, int]:
        """
        Decodes segments of a domain name to a string

        Parts are concatenated by `.`; a trailing dot is added for the NULL termination
        Decoding works as <len_a><a><len_b><b> ... where len_a = 1 byte

        @param binHexStrToDecode: Binary encoded hex string to decode
        @param offset: Absolute byte offset (from very start of message) to start with for encoding
        @return: Decoded string in the format `example.com.`, absolute offset pointing to end of decoded name
        """
        def checkOffset(binHexStrToDecode: bytes, offset: int):
            if offset >= len(binHexStrToDecode):
                msg = f"Offset too big! ({offset} given, max by binHexStrToDecode is {len(binHexStrToDecode)-1})"
                raise ValueError(msg)
            if offset < 0:
                raise ValueError("Offset too small (must be positive)!")

        checkOffset(binHexStrToDecode, offset)

        domainNameStrDecoded = ""
        offsetNew = offset

        while True:
            qNameLen = binHexStrToDecode[offsetNew]
            if qNameLen == 0:
                # Consider the null termination offset for ending in labels
                offsetNew += 1
                # print("Found zero octet")         # Debug print
                break

            # Check if is a ptr
            PTR_BITMASK = 0b11000000
            PTR_FUTURE_BITMASK1 = 0b1000000
            PTR_FUTURE_BITMASK2 = 0b0100000
            PTR_GENERIC_OFFSET = BYTE * 2
            # TODO: The ptr should be restricted to where it is allowed (only meaningful sections) to point (technically according to the RFC everywhere is valid but it's not a good idea to allow this) to and not anywhere in the data stream (MSc)
            if (binHexStrToDecode[offsetNew] & PTR_BITMASK) == PTR_BITMASK:
                # Ptr found
                PTR_OFFSET_BITMASK = 0b11111111 - PTR_BITMASK       # Inversion of PTR_BITMASK
                # (1.) Mask ptr bits away and (2.) move to the left (by 8 bits) so that we can (3.) add the remaining bits (6 out of 14) in and can eval the full 14 bits as a number -> offset
                ptrOrigOffset = ((binHexStrToDecode[offsetNew] & PTR_OFFSET_BITMASK) << 8) | binHexStrToDecode[offsetNew+1]
                # print(f"Ptr points to byte pos: {ptrOrigOffset}")         # Debug print

                domainNamePart, _ = cls.decodeDomainName(binHexStrToDecode=binHexStrToDecode, offset=ptrOrigOffset)    # Since we decode a pointer we must not use the returned offset!
                domainNameStrDecoded = domainNameStrDecoded + domainNamePart

                offsetNew += PTR_GENERIC_OFFSET
                # v=== https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
                # The compression scheme allows a domain name in a message to be
                # represented as either:
                # (1) a sequence of labels ending in a zero octet
                # (2) a pointer
                # (3) a sequence of labels ending with a pointer
                break       # We must break here in case of (2) or (3)
            elif ((binHexStrToDecode[offsetNew] & PTR_FUTURE_BITMASK1) == PTR_FUTURE_BITMASK1) or ((binHexStrToDecode[offsetNew] & PTR_FUTURE_BITMASK2) == PTR_FUTURE_BITMASK2):
                offsetNew += PTR_GENERIC_OFFSET
                raise NotImplementedError("0b1000000 and 0b0100000 prefixes are reserved for future use - not allowed!")
            else:
                offsetNew += 1
                domainNamePart = binHexStrToDecode[offsetNew:offsetNew+qNameLen]
                # print(f"LABEL: {offsetNew}:{offsetNew+qNameLen} -> `{domainNamePart}`")         # Debug print

                domainNameStrDecoded = domainNameStrDecoded + domainNamePart.decode() + "."

                # Update offset by encoded QNAME portion length
                offsetNew = offsetNew + qNameLen

        return domainNameStrDecoded, offsetNew


def main():
    stdin = input()
    stdinBytes = bytes.fromhex(stdin)

    header = DnsMsgHeader(stdinBytes)
    header.print()

    if header.questionSecExists():
        qaObj = DnsMsgQA()
        qaObj.parseQuestion(header, stdinBytes)
        qaObj.printQuestion()

        # There must be an answer section only if there is a question section (therefore within question `if`)
        if header.answerSecExists():                       # FIXME: Can probably removed since we assume an answer if there is a question (MSc)
            qaObj.parseAnswer(header, stdinBytes)
            qaObj.printAnswer()


if __name__ == '__main__':
    main()
