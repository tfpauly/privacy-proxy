---
title: HTTP CONNECT DNS Metadata Header Fields
abbrev: HTTP CONNECT DNS Metadata Header Fields
docname: draft-ppw-httpbis-connect-dns-metadata-latest
date:
category: std

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: L. Pardue
    name: Lucas Pardue
    org: Cloudflare
    email: lucaspardue.24.7@gmail.com
 -
    ins: T. Pauly
    name: Tommy Pauly
    org: Apple, Inc.
    email: tpauly@apple.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    email: caw@heapingbits.net

--- abstract

This document defines HTTP header fields for the exchange of DNS metadata
alongside CONNECT requests.

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

In some circumstances, such DNS metadata may be useful to clients. This is especially true for
proxy servers that may query for HTTPS records {{!I-D.ietf-dnsop-svcb-https}} to determine if
QUIC is supported. (If the HTTPS record has an "alpn" SVCB parameter containing "h3", the target
may support QUIC.) This information may influence or otherwise impact client specific connection
properties, such as the order or timing of Happy Eyeballs connection attempts. Clients may also
benefit from having the "echconfig" SVCB parameter, as that allows them to make use of
TLS Encrypted Client Hello {{!I-D.ietf-tls-esni}}. In general, SVCB parameters contain useful
origin-specific information that may augment client connection behavior.

Clients may also wish to share geo-specific information with proxies to aid resolution, e.g.,
via the use of the EDNS(0) Client Subnet mask {{!RFC7871}}. This is useful for upstream
resolvers that use geo-specific inforamtion for traffic engineering purposes.

This document specifies HTTP header fields that proxy servers may use to relay this DNS-specific
between clients and proxies to accompany CONNECT and CONNECT-UDP requests and responses.

## Requirements

{::boilerplate bcp14}

# DNS Metadata header fields {#header-fields}

This section specifies two types of header fields for DNS metadata, including:

1. SVCB parameter request and response header fields. These are used by clients
   to query specific SVCB parameters from an SVCB or HTTPS resource record, and
   by servers to respond to queries.
2. Client subnet request field. This is used to convey client subnet
   information to a proxy to assist in DNS resolution.

## The SVCB Parameter Request Header Field {#svcb-params-request}

Clients can request SVCB parameters with the Structured Header
{{!STRUCT=I-D.ietf-httpbis-header-structure}} "DNS-SVCB-Params". Its value MUST
be an sf-list whose members are sf-string that MUST NOT contain parameters. Its
ABNF is:

~~~ abnf
DNS-SVCB-Params = sf-list
~~~

Each list member corresponds to a SvcParamKey.

Example:

~~~ example
HEADERS
:method = CONNECT
:authority = target.example.com:443
dns-svcb-params = "alpn", "echconfig"
~~~

## The SVCB Parameter Response Header Field {#svcb-params-response}

A proxy server that receives a request with "DNS-SVCB-Params" MAY respond with
the Structured Header "DNS-SVCB-Params" response header field. Its value MUST be
an sf-list whose members are sf-string that MUST contain parameters.

~~~ abnf
DNS-SVCB-Params = sf-list
~~~

Each list member corresponds to a SVCB TargetName in the SVCB or HTTPS record,
if present. Parameters correspond to the SvcParam key-value pairs for the
TargetName. SvcParamValue MUST be encoded as sf-string.

Proxy servers MUST NOT include "DNS-SVCB-Params" response header field if the
corresponding request did not include a "DNS-SVCB-Params".

The following request shows a CONNECT request listing the "alpn" and "echconfig"
parameters from the HTTPS record, if present:

Assuming target.example.com had a SVCB resource record of the following type:

~~~ diagram
target.example.com. ; A hosting provider.
   pool  7200 IN HTTPS 1 h3pool alpn=h2,h3 echconfig="123..."
                 HTTPS 2 .      alpn=h2 echconfig="abc..."
~~~

The CONNECT response might include the following headers:

~~~ example
HEADERS
:method = CONNECT
:status = 200
dns-svcb-params = "h3pool";alpn="h2,h2";echconfig="123...",
                  "target.example.com";alpn="h2";echconfig="abc..."
~~~

[[OPEN ISSUE: add TTL in the repsonse, or in a separate header]]

## Client Subnet Header

TODO: writeme

# IANA Considerations

TODO

# Security Considerations {#sec-considerations}

The "DNS-SVCB-Params" header in {{svcb-params-response}} does not include any DNSSEC information. Clients that
depend on the contents of the SVCB record being DNSSEC-validated MUST NOT use this metadata without
otherwise fetching the record and its corresponding RRSIG record and locally verifying its contents.
