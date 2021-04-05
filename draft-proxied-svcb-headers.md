---
title: HTTP header fields for utilizing SVCB and HTTPS RRs via proxies
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
 -
    ins: E. Nygren
    name: Erik Nygren
    org: Akamai Technologies
    email: erik+ietf@nygren.org

--- abstract

This document defines a mechanism to utilize Service Binding (SVCB and
HTTPS) DNS records through HTTP proxies while using the proxies
to perform the SVCB record lookups.  This includes defining HTTP header
fields for passing DNS metadata in HTTP responses.

--- middle

# Introduction

CONNECT {{!RFC7231}} and CONNECT-UDP {{!I-D.ietf-masque-connect-udp}}
are HTTP methods (referred hereafter as "CONNECT*") that
clients may use to establish TCP or UDP flows to target servers. Once proxy servers establish
these flows, proxy servers treat allocated flows as opaque byte or datagram streams respectively.
Clients specify the target in authority-form (Section 5.3 of {{!RFC7230}}), including the name or
IP address of the server along with a port number. When using a name instead of an IP address, the
proxy server locally resolves the name to an IPv4 or IPv6 address with A or AAAA queries. As previously
defined, clients do not see these A or AAAA answers.

*TODO*: some CONNECT* methods may be moving away from specifying the target
in authority-form (and may use something closer to what is specified in rfc8441)
and we should update accordingly.  

Clients using Service Binding (SVCB or HTTPS) records {{!SVCB=I-D.ietf-dnsop-svcb-https}}
might need to perform additional DNS resolutions prior to issuing a CONNECT* request, as clients
connect to the "alternative endpoint" specified by the SVCB record (Section 3.2 of {{SVCB}}),
which includes a TargetName that may be distinct from the server name.

These records can influence client behavior even when clients are not directly interacting with
target IP addresses. The records can be used to determine which application-level protocols
are supported by an endpoint. These records also can include a TLS Encrypted Client Hello
{{!I-D.ietf-tls-esni}} configuration, which can be used in protecting the end-to-end TLS handshake.

It is not always optimal for a client that wants to use SVCB to perform a separate
DNS resolution prior to using a CONNECT* proxy, for a couple reasons:

1. The extra DNS lookup incurs a performance penalty in delaying the client's
connection establishment, which might be wasted if there aren't any SVCB records present.

2. If the client is using the proxy for providing additional privacy, performing
DNS lookups without going through the proxy might disclose the client's destination
to an additional party.

3. If DNS responses vary based on the client's network location, DNS lookups performed by the
client might not be appropriate for a connection made via the proxy.

This document specifies a mechanism for clients to utilize SVCB records
through proxies supporting this specification while reducing the need
for performing additional DNS lookups:

1. Clients provide additional information in HTTP request header fields,
   allowing the proxy to perform appropriate SVCB lookups alongside
   its AAAA and A lookups.

2. Proxies return HTTP response header fields specified in this
   document while opportunistically establishing connections.

3. Services with no SVCB records will be indicated as such
   by the proxy, allowing clients to proceed with the opportunistically
   established connection.  For services with SVCB records,
   the proxy will provide enough information to allow clients
   to decide whether they can proceed with using the connection
   or whether the client needs to establish a new connection
   through the proxy to an alternative endpoint specified
   in a SVCB record.

4. For subsequent CONNECT* requests, clients provide information
   about the service name.  The proxy uses this to provide
   refreshed SVCB records, and the proxy also continues to
   provide additional information to the client about how
   it established any given connection.

*TODO*: bikeshed on the names for these headers.

This document defines a new request header:

* Proxy-DNS-Request: requests that a proxy provide information
  from DNS lookups in its response, including AAAA/A/CNAME
  information used by the proxy in making its connection,
  as well as SVCB records for a name specified in this header.

This document also defines two new response headers:

* Proxy-DNS-SVCB: encodes SVCB records associated with requested name.
* Proxy-DNS-Used: encodes DNS information used by the Proxy for making this connection.

*TODO*: do we need a Terminology section, or a reference to Section 1.4 of {{SVCB}} as well as {{!RFC8499}}?

## Requirements

{::boilerplate bcp14}


# Definitions of request and response header fields

## Proxy-DNS-Request Request Header Field {#proxy-dns-request}

Clients can send the Structured Header {{!RFC8941}} "Proxy-DNS-Request"
to request that proxies send them DNS-related information.
Its value MUST be an sf-item whose type is sf-string followed by a set of parameters.

Its ABNF is:

~~~ abnf
Proxy-DNS-Request = sf-item
~~~

The item value is the name of a SVCB DNS query name.  This is the service
name, possibly prepended with a label ({{SVCB}} Section 2.3).
For example, "example.com" or "_foo.example.com" or "_8443._bar.api.example.com".

*TODO*: Should this have a trailing "." to be an FQDN?

The item has the following parameters:

* t: The DNS RR type of the DNS query name, which MUST be specified
  as an sf-integer (so 64 for SVCB and 65 for HTTPS).  If not
  specified, the value of 65 (HTTPS) is the default.

* wait: The maximum time in milliseconds the proxy should wait before responding to
  the CONNECT* request while waiting for the SVCB resolution to
  complete, specified as an sf-integer.  The proxy MAY choose to not
  wait this long before responding.  If this value is less than 1
  then proxy SHOULD NOT wait for a SVCB resolution and should
  only include SVCB information it has cached.
  If this parameter is not specified, proxies are free to choose
  a reasonable default.

* params: Clients can optionally limit which SVCB parameters they'd like
  to receive by specifying this parameter.  Its value MUST
  be an inner-list whose members are sf-integer items.
  Each list member corresponds to the numeric version of an SvcParamKey.
  If not specified, proxies SHOULD return the full set of SVCB parameters
  for each SVCB RR.

* version: Clients can optionally specify which versions of this specification
  they support.  Its value MUST be an inner-list whose members are sf-string
  values.  This draft specifies version "draft-01".

* u: Clients can indicate whether they want DNS information about
  the IP address that the proxy connected to through this parameter.
  Its value MUST be an sf-boolean.

*TODO*: Remove or update the "version" functionality prior to publication.

Proxies MUST ignore new parameters they don't understand.

Proxies MUST ignore the header entirely if a version parameter is specified
and they do not support any of the listed versions.

### Example Proxy-DNS-Request

For example, a client wanting to receive both DNS information about
the IP address that the proxy connected to, and for just alpn (1) and echconfig (5) parameters
for the SVCB RRset named "_foo.svc.example.com" would send a request:

~~~ example
HEADERS
:method = CONNECT
:authority = svc.example.com:443
proxy-dns-request = "_foo.svc.example.com"; t=64; wait=400; params=(1 5); u; version=("draft-01")
~~~

Additional examples are below in {#examples}.


## Proxy-DNS-SVCB Response Header Field {#proxy-dns-svcb}

A proxy server that receives a request with "Proxy-DNS-Request" MAY respond with
the Structured Header "Proxy-DNS-SVCB" response header fields.

The intent of this header is to provide SVCB-optional clients with
enough information to implement {{SVCB}} without performing additional
DNS lookups, including Sections 3 and 8.  This includes providing them
with a list of alternative endpoints, as well as being explicit about
whether SVCB records do and do not exist.

The value of "Proxy-DNS-SVCB" MUST be an sf-list whose members are
sf-string, each of which MUST contain parameters.

~~~ abnf
Proxy-DNS-SVCB = sf-list
~~~

Each list member is an sf-string that represents the TargetName of a
single received SVCB or HTTPS record, resulting from the resolving the
SVCB DNS query name in the Proxy-DNS-Request for the specified RR
type.  The Parameters associated with each list member correspond to
the SvcParam key-value pairs for that record, the priority of the
record, and the TTL of the record.

If the TargetName in the SVCB record is "." then the Proxy MUST expand this to the
owner name of the SVCB RR, including the owner name as the list member's item value.

The priority of the record MUST be a parameter with the key "priority", and a value as an
sf-integer.

The TTL of the record MUST be a parameter with the key "ttl", and a value as an sf-integer.
This value must be the minimum TTL value of any CNAME or SVCB record encountered while
resolving this SVCB record.

SvcParams are represented with a parameter string constructed
prepending the string "key" to the numeric version of the
SvcParamKey. For example, the ALPN SvcParamKey, with the numeric value
1, would have a parameter key "key1". The value of each parameter MUST
be an sf-binary item that contains the bytes of the SvcParamValue.

If Proxy-DNS-Request included a "params" parameter, the proxy server
MAY filter the SvcParams to only include SvcParams whose keys were
included in the "params" list.  Severs MAY include additional
SvcParams.  In particular, servers SHOULD include the "mandatory"
parameter if present, which would be presented as "key0", along with
any parameters that are defined as mandatory for that record.

Proxy servers MUST NOT include the "Proxy-DNS-SVCB" response header field if the
corresponding request did not include a "Proxy-DNS-Request".

Proxy servers MUST attempt to resolve the SVCB DNS query name to
obtain the SVCB RRset to return in this header.  If this resolves to a
SVCB AliasMode record, proxy servers MUST resolve the TargetName of
that AliasMode record to obtain a ServiceMode record.  Both
resolutions MUST use the same RR type specified in the "t" parameter
of Proxy-DNS-Request.

Multiple factors influence which records are returned in this header:

* If the SVCB DNS query name resolves to a SVCB ServiceMode record,
  only the ServiceMode records SHALL be included in the Proxy-DNS-SVCB
  list.

* If the SVCB DNS query name resolves to a SVCB AliasMode record, and
  if the TargetName of the SVCB AliasMode record resolves to a SVCB
  ServiceMode RRSet, only the ServiceMode records SHALL be included in
  the Proxy-DNS-SVCB list.
  
* If the SVCB DNS query name resolves to a SVCB AliasMode record, and
  if the TargetName of a SVCB AliasMode record does not resolve to any
  ServiceMode records, the Proxy-DNS-SVCB list SHALL include a single
  item containing the AliasMode TargetName and "priority=0".

* If no SVCB records are found authoritatively (i.e., a "NOERROR" or
  "NXDOMAIN" response when resolving the SVCB DNS query name specified
  in the Proxy-DNS-Request header), the list MUST contain a single
  entry with the item value of ".", indicating that the name has no
  SVCB records.  This special value of "." MUST NOT be returned in
  error conditions such as timeouts.  The value of the "ttl" parameter
  MUST be the TTL of this authoritative DNS response.

* If an error condition is encountered (such as a timeout, loop, or
  invalid record), the Proxy-SVCB-DNS header MUST contain an empty list
  (and thus not be returned).


### Example Proxy-DNS-SVCB response

As an example, assume that the server resolved the SVCB DNS query name
"example.com" and RR type 65 (HTTPS) as follows:

~~~ diagram
   example.com.     7200 IN HTTPS 0 foo.svc.example.net.
   foo.svc.example.net 1800 IN CNAME svc.example.net.
   svc.example.net. 3600 IN HTTPS 1 svc2.example.net. alpn=h2,h3 echconfig="123..."
   svc.example.net. 3600 IN HTTPS 2 . alpn=h2 echconfig="abc..."
~~~

A successful CONNECT response would include the following headers, if the client requested both
"alpn" and "echconfig":

~~~ example
HEADERS
:method = CONNECT
:status = 200
proxy-dns-svcb = "svc2.example.net.";priority=1;ttl=1800;key1=:aDIsaDM=:;key5=:MTIz...:,
                 "svc.example.net.";priority=2;ttl=1800;key1=:aDI=:;key5=:YWJj...:
~~~


## Proxy-DNS-Used Response Header Field {#proxy-dns-used}

A proxy server that receives a request with "Proxy-DNS-Request" with MAY respond with
the Structured Header "Proxy-DNS-Used" response header fields. The value of
"Proxy-DNS-Used" MUST be an sf-list whose members are sf-string, each of
which MUST contain parameters.

~~~ abnf
Proxy-DNS-Used = sf-list
~~~

The intent of this header is to provide clients with enough
information to implement Section 5 of {{SVCB}}.

Proxy servers MUST NOT include the "Proxy-DNS-Used" response header field if the
corresponding request did not include a "Proxy-DNS-Request" or if its "u"
parameter had the value sf-false.

Each list member is an sf-string that represents either the IP address
(IPv4 or IPv6) that the proxy connected to for the CONNECT* request,
or the value of a DNS CNAME on the path of aliases involved in
resolving the hostname connected to by the proxy.

The last member in the list MUST have an item value that is the string
representation of the IPv6 or IPv4 address that represents the
destination of the CONNECT* from the proxy.  If this is an IPv6
address, it MUST follow the canonical string form from {{!RFC5952}}.

*TODO*: Is there an IPv4 canonical form RFC we should reference here?

If the hostname connected to by the proxy aliased to one or more CNAMEs,
these should be included at the front of the list, starting with
the CNAME that the hostname resolved to and proceeding sequentially.

Each item in the list has the following parameters:

* t: The DNS RR type of the DNS query name, which MUST be specified
  as an sf-integer (so 1 for A, 28 for AAAA, and 5 for CNAME).

* ttl: The TTL of the address or CNAME record SHOULD be included as a
  parameter with the key "ttl", whose value MUST be an sf-integer.
  If the value of of intermediate records are unavailable,
  the ttl parameter SHOULD be included on just the last list
  entry, containing the minimum TTL value across the CNAMEs.

* o: The owner name of the DNS record MAY be included.
  If this parameter is specified, its value MUST be an sf-string
  whose value is the owner name of the record.



### Example Proxy-DNS-Used response

As an example, assume that the proxy server resolved the
authority hostname of "svc.example.com" as follows:

~~~ diagram
   svc.example.com.  7200 IN CNAME  svc.example.net.
   svc.example.net.  1800 IN CNAME  svc2.example.net.
   svc2.example.net.   60 IN A      192.0.2.74
   svc2.example.net.   60 IN AAAA   2001:db8::75
   svc2.example.net.   60 IN AAAA   2001:db8::76
~~~

If the proxy connected to 2001:db8::75 then the successful CONNECT
response would include the following header:

~~~ example
HEADERS
:method = CONNECT
:status = 200
proxy-dns-used = "svc.example.net.";ttl=7200;t=5;o="svc.example.com.",
                 "svc2.example.net.";ttl=1800;t=5;o="svc.example.net.",
                 "2001:db8::75";ttl=60;t=28;o="svc2.example.net."
~~~


*TODO*: Do we need the "o=" parameter or is it redundant?
        If we include it, should it be a MUST or MAY?
        
*TODO*: Do we need to cover DNAME as well? 

*TODO*: Should a future version be able to include NS record
        and DNSSEC information?


# Proxy Behavior

Proxy servers MUST NOT take action based on SVCB records.
In particular, the ipv4hint and ipv6hint SvcParams MUST NOT
be used by proxies for making connections.

*TODO*: Discuss if this is too restrictive


# Client Behavior

Clients that are SVCB-required ({{SVCB}} Section 3) MUST perform a DNS
resolution prior to making a CONNECT* request, as they will need to
obtain SVCB records and a TargetName.

Clients that are SVCB-optional MAY use a proxy implementing this
specification to use SVCB records without performing additional DNS
resolutions.  Clients doing so MUST implement other requirements
specified in {{SVCB}} with the following providing a mechanism for
doing so through a proxy.  As an example, if the client has a valid
Proxy-DNS-SVCB header cached corresponding to a HTTPS RR (even if only
for AliasMode), the client SHOULD upgrade to the "https" scheme as
described in Section 3.5 of {{SVCB}}, which may involve abandoning a
CONNECT to port 80 through which it learned about the HTTPS RR.

If a client has a valid SVCB RRset or Proxy-DNS-SVCB cached for a
given service, it SHOULD use CONNECT* with the authority hostname and
port equal to the TargetName and port for the selected alternative
endpoint.  It also SHOULD include Proxy-DNS-Request (with a SVCB DNS
query name or the original service name to refresh its SVCB RRset
cache.

If a client has no valid SVCB RRset cached for a given service,
it SHOULD opportunistically CONNECT* with an authority hostname
of the service name.  If the response contains a Proxy-DNS-SVCB
header, the client SHOULD select an alternative endpoint
from the provided list.  Based on the selected alternative
endpoint, the client decides whether it can continue to use
this opportunistically-created connection or needs to establish
a new connection:

1) If the IP address in the Proxy-DNS-Used list matches an ipv6hint
   or ipv4hint SvcParam on the selected alternative endpoint,
   and if the port used in the CONNECT* matches the selected
   alternative endpoint, and if the transport protocol is compatible
   with the selected alpn (eg, CONNECT for "h2" and CONNECT-UDP
   for "h3"), the client SHOULD use the established connection.

2) If either the authority hostname or any of the hostnames returned
   in the Proxy-DNS-Used list match the TargetName of the selected
   alternative endpoint, and if the port used in the CONNECT* matches
   the selected alternative endpoint, and if the transport protocol is
   compatible with the selected alpn (eg, CONNECT for "h2" and
   CONNECT-UDP for "h3"), the client SHOULD use the established
   connection.

3) If no alternative endpoint has a match with either condition 1
   or 2, the client MUST NOT use the connection and will instead
   abandon it.  Clients then MUST establish a new CONNECT*
   based on the TargetName and other SvcParams from the selected
   alternative endpoint.

Note that clients MAY select to use a less preferred alternative
endpoint (if only temporarily) if it allows use of the
opportunistically established connection, but only provided
either condition 1 or 2 matches.

If a CONNECT* request does not include a Proxy-DNS-SVCB header, and if
clients do not have a cached SVCB RR, SVCB-optional clients SHOULD
proceed with using the established connection.

For all of the above, clients MUST age out information learned
about Proxy-DNS-Used and Proxy-DNS-SVCB based on the TTLs
returned in those headers.  Clients SHOULD continue to refresh
them as requests are made to the proxy.  Clients SHOULD periodically
re-evaluate if new connections need to be established based on
expiry of these TTLs.

*TODO*: Most of this section assumes ServiceMode records.
        We should better structure to handle AliasMode records.
        (I'm not sure the second condition ever applies?)
        Below is some partial text:

When Proxy-DNS-SVCB (or a cached SVCB) contains an AliasMode record,
clients SHOULD either use a connection made to the TargetName
of the AliasMode record, or they SHOULD use a connection
where any of the hostnames returned in Proxy-DNS-Used
matches the TargetName of the AliasMode record.


## SVCB-required clients

SVCB-required clients must either perform additional SVCB
DNS requests, or MUST use a proxy that is known and configured
to always return Proxy-DNS-SVCB and Proxy-DNS-Used headers.

SVCB-required clients SHOULD set high values for "wait" in
Proxy-DNS-Request and MUST treat the absence of a Proxy-DNS-SVCB
response header as an error.

SVCB-required clients may also need to make their initial request to
an authority with no expectation of being able to use that connection.
Protocols specifying for SVCB-required clients will need to describe
what clients should use in this case.




## Interaction with Alt-Svc

*TODO*: Write this section...


## Interaction with SVCB records obtained through the DNS

*TODO*: Write this section...



# IANA Considerations

## HTTP Headers {#iana-header}

*TODO*: Move the registries below to the new HTTP-core registry.

This document registers the "Proxy-DNS-Request" and "Proxy-DNS-SVCB",
headers in the "Permanent Message Header Field Names"
<[](https://www.iana.org/assignments/message-headers)>.

~~~
  +----------------------+----------+--------+---------------+
  | Header Field Name    | Protocol | Status |   Reference   |
  +----------------------+----------+--------+---------------+
  | Proxy-DNS-Request    |   http   |  exp   | This document |
  +----------------------+----------+--------+---------------+
  | Proxy-DNS-SVCB       |   http   |  exp   | This document |
  +----------------------+----------+--------+---------------+
  | Proxy-DNS-Used       |   http   |  exp   | This document |
  +----------------------+----------+--------+---------------+
~~~

# Privacy Considerations {#priv-considerations}

Client variation in Proxy-DNS-Request may be a vector for fingerprinting.
Clients concerned about this may prefer to:
* Not include "param" and receive all SVCB parameters.
* Sort the item's parameters by their keys.
* Limit variation in the values for "wait"
  and select a wait value of 50, 100, 200,
  400, 800, or 1600.
* Not send "version" if implementing only the default
  (published RFC) version.

*TODO*: Is this a good set of "wait" values?


# Security Considerations {#sec-considerations}

The "Proxy-DNS-SVCB" header in {{proxy-dns-svcb}} and "Proxy-DNS-Used"
headers in {{proxy-dns-used}} do not include any DNSSEC
information. Clients that depend on the contents of the SVCB record
being DNSSEC-validated MUST NOT use this metadata without otherwise
fetching the record and its corresponding RRSIG record and locally
verifying its contents.

Clients relying on ECH should avoid sending anything on
opportunistically created connections until verifying whether
there is a preferred alternative service that supports ECH
which they should use.


# Appendix: Additional Examples {#examples}


*TODO*: Add additional examples.
