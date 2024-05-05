# DNS message parser
(Partial) Python 3 implementation of a DNS message parser (supports A, AAAA and CNAME record types (qtypes) and IPv4/IPv6)

Based on a input binary hex stream (like: `a01d81800001000100000000076578616d706c6503636f6d0000010001c00c0001000100001bbc00045db8d822`) it prints:
```
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40989
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;example.com.           IN      A

;; ANSWER SECTION:
example.com.            7100    IN      A       93.184.216.34
```

The tool returns similar (but less) output to [`dig`](https://linux.die.net/man/1/dig).

# Based on RFCs:
* [Domain Names – Concepts and Facilities](https://datatracker.ietf.org/doc/html/rfc1035)
* [Domain Names – Implementation and Specification](https://datatracker.ietf.org/doc/html/rfc1034)
* [DNS Extensions to Support IP Version 6](https://datatracker.ietf.org/doc/html/rfc3596)
