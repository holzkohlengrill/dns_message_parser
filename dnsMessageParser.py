# Enter your code here. Read input from STDIN. Print output to STDOUT
# RFCs:
# * [Domain Names – Concepts and Facilities](https://datatracker.ietf.org/doc/html/rfc1035)
# * [Domain Names – Implementation and Specification](https://datatracker.ietf.org/doc/html/rfc1034)

# RFC 2181 – Clarifications to the DNS Specification. (englisch).
# RFC 2782 – A DNS RR for specifying the location of services (DNS SRV). (englisch).

from ctypes import BigEndianStructure, c_uint16, sizeof


class DnsMsgHeader(BigEndianStructure):   # Network Byte order: Big Endian (https://twu.seanho.com/09spr/cmpt166/lectures/29-dns.pdf, slide 7)
    """
    DNS message header object
    
    :param _fields_: Bit field definitions; must have same type to avoid padding (if `_pack_ = 1` is not used or not working); we must choose c_uint16 (no negative numbers; biggest field is 16 bit)
    """
    
    _fields_ = [                     # TODO: check if we can do something like: `("ID", c_uint8*2, 16)` and if we benefit from that (that might help reducing the data type sizes) (MSc)
        ("ID", c_uint16, 16),        # Identifier assigned by the program that generates any kind of query
        ("QR", c_uint16, 1),
        ("OPCODE", c_uint16, 4),     # 0: standard query (QUERY), 1: inverse query (IQUERY), 2: server status request (STATUS), 3-15: reserved for future use
        ("AA", c_uint16, 1),         # Authoritative Answer: NS is a authority for domain name in question
        ("TC", c_uint16, 1),         # TrunCation (if is truncated due to length greather than permitted by transm. ch.)
        ("RD", c_uint16, 1),         # Recursion Desired?
        ("RA", c_uint16, 1),         # Recursion avail?
        ("Z", c_uint16, 3),          # Always 0 (future use)
        ("RCODE", c_uint16, 4),      # Response code (* error, no error, ...)
        ("QDCOUNT", c_uint16, 16),   # Num. of entries in question section
        ("ANCOUNT", c_uint16, 16),   # Num. of entries in answer section
        ("NSCOUNT", c_uint16, 16),   # Num. of NS resource records (RR) in auth. records section
        ("ARCOUNT", c_uint16, 16),   # Num. of RR in add. records section
    ]
        
    OpCodeLUT = {
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
    
    RCodeLUT = {        # = status
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


# TODO: Check whether we can we use the same class for question and answer? (-> same struct) (MSc)
class DnsMsgQuestion(BigEndianStructure):   # Network Byte order: Big Endian (https://twu.seanho.com/09spr/cmpt166/lectures/29-dns.pdf, slide 7)
    """
    DNS message question object
    We have this structure for each "question"/query -> QDCOUNT (usually 1)
    
    :param _fields_: Bit field definitions; must have same type to avoid padding (if `_pack_ = 1` is not used or not working); we must choose c_uint16 (no negative numbers; biggest field is 16 bit)
    """
    QtypeLUT = {            # Value description: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
        # Type (= subset of QTYPE)
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
        # QTYPE
        252: "AXFR",
        253: "MAILB",
        254: "MAILA",
        255: "*",
    }
    
    ClassTypeLUT = {        # Value description: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
        1: "IN",
        2: "CS",
        3: "CH",
        4: "HS",
    }


def decodeDomainName(binHexStrToDecode: bytes, offset: int = 0) -> (str, bytes):
    """
    Decodes segments of a domain name to a string
    
    Parts are concatenated by `.`; a trailing dot is added for the NULL termination
    Decoding works as <len_a><a><len_b><b> ... where len_a = 1 byte

    @param binHexStrToDecode: Binary encoded hex string to decode
    @param offset: Absolute byte offset (from very start of message) to start with for encoding
    @return: Decoded string in the format `example.com.`, absolute offset pointing to end of decoded name
    """
    # TODO: Does not support yet pointers (MSc)
    
    def checkOffset(binHexStrToDecode: bytes, offset: int):
        if offset >= len(binHexStrToDecode):
            raise ValueError(f"Offset too big! ({offset} given, max by binHexStrToDecode is {len(binHexStrToDecode)-1})")
        if offset < 0:
            raise ValueError("Offset too small (must be positive)!")
    
    checkOffset(binHexStrToDecode, offset)
    
    binHexStrToDecodeTruncated = binHexStrToDecode[offset:]
    domainNameStrDecoded = ""
    offsetNew = offset
    while True:
        # qname_len_old = binHexStrToDecodeTruncated[0]
        qname_len = binHexStrToDecode[offsetNew]
        # print(f"qname_len_old: {qname_len_old}, qname_len: {qname_len}")
        if qname_len == 0:
            # Consider the null termination offset
            # binHexStrToDecodeTruncated = binHexStrToDecodeTruncated[1:]
            offsetNew += 1
            break
        # domainNamePart_old = binHexStrToDecodeTruncated[1:1+qname_len]
        offsetNew += 1
        domainNamePart = binHexStrToDecode[offsetNew:offsetNew+qname_len]
        # print(f"domainNamePart_old: {domainNamePart_old}, domainNamePart: {domainNamePart} (off{offsetNew},len{qname_len})")
        
        domainNameStrDecoded = domainNameStrDecoded + domainNamePart.decode() + "."
        
        # Truncate binHexStrToDecodeTruncated by encoded QNAME portion
        # binHexStrToDecodeTruncated = binHexStrToDecodeTruncated[len(domainNamePart)+1:]
        offsetNew = offsetNew + qname_len

    # offsetNew = len(binHexStrToDecode) - len(binHexStrToDecodeTruncated) #+ offset+1
    return domainNameStrDecoded, offsetNew


# TODO: Create one DNS message object via multiple inheritance from header, question and answer (MSc)

def main():
    stdin = input()
    
    stdinBytes = bytes.fromhex(stdin)
    headerBytes = stdinBytes[:sizeof(DnsMsgHeader)]

    # #############################
    # Header processing
    # #############################
    header = DnsMsgHeader.from_buffer_copy(headerBytes)
    # TODO: move print to class method (MSc)
    COMMENT_PREFIX = ";; "
    
    HEADER_PREFIX = "->>HEADER<<- "
    print(f"{COMMENT_PREFIX}{HEADER_PREFIX}opcode: {DnsMsgHeader.OpCodeLUT.get(header.OPCODE, 'INVALID')}, status: {DnsMsgHeader.RCodeLUT.get(header.RCODE, 'INVALID')}, id: {header.ID}")      # TODO: Use cls (classmethod) instead of DnsMsgHeader (MSc)
    concatedFlagStr = " ".join(['qr' if header.QR else '', 'rd' if header.RD else '', 'ra' if header.RA else ''])       # TODO: move this to class method
    print(f"{COMMENT_PREFIX}flags: {concatedFlagStr}; QUERY: {header.QDCOUNT}, ANSWER: {header.ANCOUNT}, AUTHORITY: {header.NSCOUNT}, ADDITIONAL: {header.ARCOUNT}")
    print()
    
    # TODO implement Z eval (must be always 0); though we could also ignore it (MSc)
    
    # TODO: move this eval to class method (MSc)
    questionSec = True if header.QDCOUNT > 0 else False
    answerSec = True if header.ANCOUNT > 0 else False
    
    # #############################
    # Question section processing
    # #############################
    if questionSec:
        HEADER_QUESTION = "QUESTION SECTION:"
        print(f"{COMMENT_PREFIX}{HEADER_QUESTION}")
        
        questionSecsOffset = 0
        # Per question section
        for _ in range(header.QDCOUNT):
            # QNAME = domain name
            domainName, questionSecsOffset = decodeDomainName(binHexStrToDecode=stdinBytes, offset=sizeof(DnsMsgHeader))

            # QTYPE
            LEN_QTYPE = 2       # bytes
            qtypeEndPos = questionSecsOffset+LEN_QTYPE
            qtype = stdinBytes[questionSecsOffset:qtypeEndPos]
            questionSecsOffset += LEN_QTYPE
            # print(f"qtype: `{int.from_bytes(qtype, 'big')}` (= {DnsMsgQuestion.QtypeLUT[int.from_bytes(qtype, 'big')]})")
            
            # QCLASS
            LEN_QCLASS = 2      # bytes
            qclassEndPos = questionSecsOffset+LEN_QCLASS
            qclass = stdinBytes[questionSecsOffset:qclassEndPos]
            questionSecsOffset += LEN_QCLASS
            # print(f"qclass: `{int.from_bytes(qclass, 'big')}` (= {DnsMsgQuestion.ClassTypeLUT[int.from_bytes(qclass, 'big')]})")
        
            print(f"questionSecsOffset: {questionSecsOffset}")
            print(f";{domainName: <24}{DnsMsgQuestion.ClassTypeLUT[int.from_bytes(qclass, 'big')]: <9}{DnsMsgQuestion.QtypeLUT[int.from_bytes(qtype, 'big')]}")
            print()
        
                
        # #############################
        # Answer section processing
        # #############################
        # There must be an answer section only if there is a question section (therefore within question if)
        HEADER_ANSWER = "ANSWER SECTION:"
        print(f"{COMMENT_PREFIX}{HEADER_ANSWER}")
        
        answerSecOffset = questionSecsOffset
        # Per answer section
        for _ in range(header.ANCOUNT):
            answerBody = stdinBytes[answerSecOffset:]
            if answerSec:
                # Check name is a ptr
                PTR_BITMASK = 0b11000000
                if (stdinBytes[answerSecOffset] & PTR_BITMASK) == PTR_BITMASK:
                    # Ptr found
                    print("IS PTR!")
                    PTR_OFFSET_BITMASK = 0b11111111 - PTR_BITMASK       # Inversion of PTR_BITMASK
                    # (1.) Mask ptr bits away and (2.) move to the left (by 8 bits) so that we can (3.) add the remaining bits (6 out of 14) in and can eval the full 14 bits as a number -> offset
                    ptrOrigOffset = ((stdinBytes[answerSecOffset] & PTR_OFFSET_BITMASK) << 8) | stdinBytes[answerSecOffset+1]
                    print(f"offset is: {ptrOrigOffset} bytes")

                    domainNameAnsw, _ = decodeDomainName(binHexStrToDecode=stdinBytes, offset=ptrOrigOffset)
                    print(f"newoffset: {_}, old: {answerSecOffset}")
                # FIXME: Adapt string to answer sec (MSc)
                # FIXME: Rename DnsMsgQuestion to make it generic (MSc)
                print(f";{domainNameAnsw: <24}{DnsMsgQuestion.ClassTypeLUT[int.from_bytes(qclass, 'big')]: <9}{DnsMsgQuestion.QtypeLUT[int.from_bytes(qtype, 'big')]}")
                print()
            
            
            
            
            
            
            
            
            
            
            
            
                # FIXME: The ptr should be restricted to where it is allowed (only meaningful sections) to point (technically according to the RFC everywhere is valid but it's not a good idea to allow this) to and not anywhere in the data stream (MSc)
                
                # Read ptr value
                # ptrRefStartDataStream = stdinBytes[ptrOrigOffset:]
                
                # TODO: Unify this with the QNAME loop as a function (MSc)
                while True:
                    # Check if we did not reached a NULL termination or pointer
                    # NULL termination (end of label)
                    if stdinBytes[ptrOrigOffset] != 0:
                        break
                    # Check if we did not reach a NULL termination or pointer
                    elif (stdinBytes[ptrOrigOffset] & PTR_BITMASK) == PTR_BITMASK:
                        # TODO: create a recursive call to check chained references (MSc)
                        pass
                    
                    
            else:
                # No ptr
                print("NOO PTR")


if __name__ == '__main__':
    main()
