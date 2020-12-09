---
title: HTTP Header Fields for Proxied SVCB Metadata
abbrev: Proxied SVCB Headers
docname: draft-proxied-svcb-headers-latest
date:
category: std

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: T. Pauly
    name: Tommy Pauly
    org: Apple, Inc.
    email: tpauly@apple.com

--- abstract

This document defines HTTP header fields for the passing Service Binding (SVCB) DNS metadata
in HTTP responses.

--- middle

# Introduction

CONNECT {{!RFC7231}} and CONNECT-UDP {{!I-D.ietf-masque-connect-udp}} are HTTP methods that
clients may use to establish TCP or UDP flows to target servers. Once proxy servers establish
these flows, proxy servers treat allocated flows as opaque byte or datagram streams respectively.
Clients specify the target in authority-form (Section 5.3 of {{!RFC7230}}), including the name or
IP address of the server along with a port number. When using a name instead of an IP address, the
proxy server locally resolves the name to an IPv4 or IPv6 address with A or AAAA queries. The
client does not see these A or AAAA answers, as they are only relevant to the proxy in establishing
a connection to the target.

In some circumstances, some DNS metadata may be useful to clients. This is especially true for
information contained in Service Binding (SVCB or HTTPS) records {{!I-D.ietf-dnsop-svcb-https}}.
These records can influence client behavior even when clients are not directly interacting with
target IP addresses. The records can be used to determine which application-level protocols
are supported by an endpoint. These records also can include a TLS Encrypted Client Hello
{{!I-D.ietf-tls-esni}} configuration, which can be used in protecting the end-to-end TLS handshake.

This document specifies HTTP header fields that proxy servers may use to relay information retrieved
from SVCB records from proxy servers to clients when using CONNECT or CONNECT-UDP.

## Requirements

{::boilerplate bcp14}

# SVCB Request Header Field {#svcb-params-request}

Clients can request SVCB parameters with the Structured Header
{{!STRUCT=I-D.ietf-httpbis-header-structure}} "DNS-SVCB-Keys". Its value MUST
be an sf-list whose members are sf-integer items that MUST NOT contain parameters. Its
ABNF is:

~~~ abnf
DNS-SVCB-Keys = sf-list
~~~

Each list member corresponds to the numeric version of an SvcParamKey.

For example, a client wanting to receive ALPN and ECH Config parameters would
send a request for 1 (alpn) and 5 (echconfig):

~~~ example
HEADERS
:method = CONNECT
:authority = svc.example.com:443
dns-svcb-keys = 1, 5
~~~

# SVCB Response Header Fields {#svcb-params-response}

A proxy server that receives a request with "DNS-SVCB-Keys" MAY respond with
the Structured Header "DNS-SVCB-Params" response header fields. The value of
"DNS-SVCB-Params" MUST be an sf-list whose members are sf-string, each of
which MUST contain parameters.

~~~ abnf
DNS-SVCB-Params = sf-list
~~~

Each list member is an sf-string that represents the TargetName of a single received
SVCB or HTTPS record. The Parameters associated with each list member correspond
to the SvcParam key-value pairs for that record, the priority of the record, and the
TTL of the record.

The priority of the record MUST be a parameter with the key "priority", and a value as an
sf-integer. Alias forms, with priority 0, MUST NOT be included.

The TTL of the record MUST be a parameter with the key "ttl", and a value as an sf-integer.

Each SvcParam that matches a key requested by the client is a parameters with a key
that is the character "p" followed by the numeric version of the SvcParamKey. For example,
the ALPN SvcParamKey, with the numeric value 1, would have a parameter key "p1". The value
of each parameter MUST be an sf-binary item that contains the bytes of the SvcParamValue.

Proxy servers MUST NOT include "DNS-SVCB-Params" response header field if the
corresponding request did not include a "DNS-SVCB-Keys". Servers also MUST NOT include
specific SvcParamKey values that were not requested.

As an example, assume that the server received the following "svc.example.com" SVCB records:

~~~ diagram
   svc.example.com. 3600 IN HTTPS 1 svc2.example.com. alpn=h2,h3 echconfig="123..."
   svc.example.com. 3600 IN HTTPS 2 . alpn=h2 echconfig="abc..."
~~~

A successful CONNECT response would include the following headers, if the client requested both
"alpn" and "echconfig":

~~~ example
HEADERS
:method = CONNECT
:status = 200
dns-svcb-params = "svc2.example.com.";priority=1;ttl=3600;p1=:aDIsaDM=:;p5=:MTIzLi4u:,
                  "svc.example.com.";priority=2;ttl=3600;p1=:aDI=:;p5=:YWJjLi4u:
~~~

# IANA Considerations

## HTTP Headers {#iana-header}

This document registers the "DNS-SVCB-Keys" and "DNS-SVCB-Params",
headers in the "Permanent Message Header Field Names"
<[](https://www.iana.org/assignments/message-headers)>.

~~~
  +----------------------+----------+--------+---------------+
  | Header Field Name    | Protocol | Status |   Reference   |
  +----------------------+----------+--------+---------------+
  | DNS-SVCB-Keys        |   http   |  exp   | This document |
  +----------------------+----------+--------+---------------+
  | DNS-SVCB-Params      |   http   |  exp   | This document |
  +----------------------+----------+--------+---------------+
~~~

# Security Considerations {#sec-considerations}

The "DNS-SVCB-Params" header in {{svcb-params-response}} does not include any DNSSEC information. Clients that
depend on the contents of the SVCB record being DNSSEC-validated MUST NOT use this metadata without
otherwise fetching the record and its corresponding RRSIG record and locally verifying its contents.
