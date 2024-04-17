# Enter your code here. Read input from STDIN. Print output to STDOUT
# RFCs:
# * [Domain Names – Concepts and Facilities](https://datatracker.ietf.org/doc/html/rfc1035)
# * [Domain Names – Implementation and Specification](https://datatracker.ietf.org/doc/html/rfc1034)

# RFC 2181 – Clarifications to the DNS Specification. (englisch).
# RFC 2782 – A DNS RR for specifying the location of services (DNS SRV). (englisch).

from ctypes import BigEndianStructure, c_uint16, c_uint8, sizeof


class DnsMsgHeader2(BigEndianStructure):   # Network Byte order: Big Endian (https://twu.seanho.com/09spr/cmpt166/lectures/29-dns.pdf, slide 7)
    """
    DNS message object
    
    :param _fields_: Bit field definitions; must have same type to avoid padding (if `_pack_ = 1` is not used or not working); we must choose c_uint16 (no negative numbers; biggest field is 16 bit)
    """
    
    _pack_ = 1                      # Avoid auto-padding to 4 bytes; we align on 1-bit byte base (apparently this might not work always; as a workaround one might want to set all __fields_ tuple types to the biggest field which is 16 bit -> c_uint16)
    _fields_ = [
        ("ID", c_uint16, 16),       # Identifier assigned by the program that generates any kind of query
        ("QR", c_uint8, 1),         # Query (0) or Response (1)
        ("OPCODE", c_uint8, 4),     # 0: standard query (QUERY), 1: inverse query (IQUERY), 2: server status request (STATUS), 3-15: reserved for future use
        ("AA", c_uint8, 1),         # Authoritative Answer: NS is a authority for domain name in question
        ("TC", c_uint8, 1),         # TrunCation (if is truncated due to length greather than permitted by transm. ch.)
        ("RD", c_uint8, 1),         # Recursion Desired?
        ("RA", c_uint8, 1),         # Recursion avail?
        ("Z", c_uint8, 3),          # Always 0 (future use)
        ("RCODE", c_uint8, 1),      # Response code, see (RCODE): https://datatracker.ietf.org/doc/html/rfc1035#autoid-41
        ("QDCOUNT", c_uint16, 16),  # Num. of entries in question section
        ("QDCOUNT", c_uint16, 16),  # Num. of entries in question section
        ("ANCOUNT", c_uint16, 16),  # Num. of entries in answer section
        ("NSCOUNT", c_uint16, 16),  # Num. of NS resource records (RR) in auth. records section
        ("ARCOUNT", c_uint16, 16),  # Num. of RR in add. records section
                                    # FIXME: with `_pack_ = 1` & non-homogeneous _fields_ types this returns a wrong value
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


class DnsMsgHeader(BigEndianStructure):   # Network Byte order: Big Endian (https://twu.seanho.com/09spr/cmpt166/lectures/29-dns.pdf, slide 7)
    """
    DNS message header object
    
    :param _fields_: Bit field definitions; must have same type to avoid padding (if `_pack_ = 1` is not used or not working); we must choose c_uint16 (no negative numbers; biggest field is 16 bit)
    """
    
    _fields_ = [                     # TODO: check if we can do something like: `("ID", c_uint8*2, 16)` and if we benefit from that (that might help reducing the data type sizes)
        ("ID", c_uint16, 16),        # Identifier assigned by the program that generates any kind of query
        ("QR", c_uint16, 1),
        ("OPCODE", c_uint16, 4),     # 0: standard query (QUERY), 1: inverse query (IQUERY), 2: server status request (STATUS), 3-15: reserved for future use
        ("AA", c_uint16, 1),         # Authoritative Answer: NS is a authority for domain name in question
        ("TC", c_uint16, 1),         # TrunCation (if is truncated due to length greather than permitted by transm. ch.)
        ("RD", c_uint16, 1),         # Recursion Desired?
        ("RA", c_uint16, 1),         # Recursion avail?
        ("Z", c_uint16, 3),          # Always 0 (future use)
        ("RCODE", c_uint16, 1),      # Response code, see (RCODE): https://datatracker.ietf.org/doc/html/rfc1035#autoid-41
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


# TODO: Check if we can we use the same class for question and answer? (-> same struct)
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


# TODO: Create one DNS message object via multiple inheritance from header, question and answer
# TODO: Check if compression is used and if we need to implement it: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4

def main():
    stdin = input()
    # print(f"stdin: `{stdin}` (type: {type(stdin)})")
    stdinBytes = bytes.fromhex(stdin)
    # print(f"{stdinBytes}\n")
    
    stdinBytes = bytes.fromhex(stdin)
    headerBytes = stdinBytes[:sizeof(DnsMsgHeader)]
    bodyBytes = stdinBytes[sizeof(DnsMsgHeader):]

    header = DnsMsgHeader.from_buffer_copy(headerBytes)
    # TODO: move print to class method
    COMMENT_PREFIX = ";; "
    HEADER_PREFIX = "->>HEADER<<- "
    print(f"{COMMENT_PREFIX}{HEADER_PREFIX}opcode: {DnsMsgHeader.OpCodeLUT.get(header.OPCODE, 'INVALID')}, status: {DnsMsgHeader.RCodeLUT.get(header.RCODE, 'INVALID')}, id: {header.ID}")      # TODO: Use cls (classmethod) instead of DnsMsgHeader
    concatedFlagStr = " ".join(['qr' if header.QR else '', 'rd' if header.RD else '', 'ra' if header.RA else ''])       # TODO: move this to class method
    print(f"{COMMENT_PREFIX}flags: {concatedFlagStr}; QUERY: {header.QDCOUNT}, ANSWER: {header.ANCOUNT}, AUTHORITY: {header.NSCOUNT}, ADDITIONAL: {header.ARCOUNT}")
    print()
    
    HEADER_QUESTION = "QUESTION SECTION:"
    print(f"{COMMENT_PREFIX}{HEADER_QUESTION}")
    
    # TODO: move eval to class method
    questionSec = True if header.QDCOUNT > 0 else False
    answerSec = True if header.ANCOUNT > 0 else False
    
    if questionSec:
        # Per question section
        for _ in range(header.QDCOUNT):
            
            # QNAME
            domainName = ""
            while True:
                qname_len = bodyBytes[0]
                if qname_len == 0:
                    # Truncate the null termination
                    bodyBytes = bodyBytes[1:]
                    break
                domainNamePart = bodyBytes[1:1+qname_len]
                domainName = domainName + domainNamePart.decode() + "."
                # print(f"domainNamePart:{domainNamePart}")
                
                # Truncate bodyBytes by QNAME portion
                bodyBytes = bodyBytes[len(domainNamePart)+1:]
            print(f"domainName: `{domainName}`")
            
            # QTYPE
            LEN_QTYPE = 2       # bytes
            qtype = bodyBytes[:LEN_QTYPE]
            # Truncate bodyBytes by QTYPE portion
            bodyBytes = bodyBytes[LEN_QTYPE:]
            print(f"qtype: `{int.from_bytes(qtype, 'big')}` (= {DnsMsgQuestion.QtypeLUT[int.from_bytes(qtype, 'big')]})")
            
            # QCLASS
            LEN_QCLASS = 2      # bytes
            qclass = bodyBytes[:LEN_QCLASS]
            # Truncate bodyBytes by QCLASS portion
            bodyBytes = bodyBytes[LEN_QCLASS:]
            print(f"qclass: `{int.from_bytes(qclass, 'big')}` (= {DnsMsgQuestion.ClassTypeLUT[int.from_bytes(qclass, 'big')]})")


    HEADER_ANSWER = "ANSWER SECTION:"
    print(f"{COMMENT_PREFIX}{HEADER_ANSWER}")
    # TODO: move eval to class method
    if answerSec:
        print(f"TODO")


if __name__ == '__main__':
    main()
