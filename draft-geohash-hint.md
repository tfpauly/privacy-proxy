---
title: The Geohash HTTP Client Hint
abbrev: Geohash CH
docname: draft-geohash-hint-latest
category: exp

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: T. Pauly
    name: Tommy Pauly
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: tpauly@apple.com


informative:
    GEOHASH:
      target: https://en.wikipedia.org/wiki/Geohash
      title: Geohash
      date: 2020

--- abstract

This documents defines an HTTP Client Hint for sharing a client's rough location
using the Geohash format.

--- middle

# Introduction {#introduction}

HTTP Client Hints {{!RFC8942}} defines a convention for HTTP headers
to communicate optional information from clients to servers as hints. This can be done
conditionally based on if a server claims supports for a particular hint.

This document defines a client hint that can be used to send a location that the client
wants to use for influencing server behavior. It uses the Geohash algorithm {{GEOHASH}}
to encode latitude and longitude coordinates into an alphanumeric token that can be truncated
to provide a less specific location.

This header is intended to be used to provide rough geolocation hints to servers in situations
where the server cannot directly ascertain the location of the client. For example, a client
that is accessing a server through a proxy or a VPN might provide a rough hint to a server
when looking up information that may vary depending on location.

This document also defines a how forward proxies can use proxy status fields to inform clients
about the result of their Geohash hints. Test

## Requirements

{::boilerplate bcp14}

# Geohash Header

The "Sec-CH-Geohash" is an Item Structured Header {{!RFC8941}}.
Its value MUST be a String, and MUST have at least 1 character and no more than 12 characters.
The ABNF is:

~~~
   Sec-CH-Geohash = sf-string
~~~

The string itself is an encoded Geohash, which uses the 32 different characters
from the "Geohash alphabet" {{GEOHASH}}.

The following example shows an encoding of the coordinates 57.64911,10.40744:

~~~
    Sec-CH-Geohash: "u4pruydqqvj"
~~~

Servers that can provide different content based on Geohash hints SHOULD include
the headers in their "Accept-CH" list.

~~~
    Accept-CH: Sec-CH-Geohash
~~~

Servers also SHOULD indicate for any cacheable content if the Geohash hint will influence
the cached content, using the "Vary" header.

~~~
    Vary: Sec-CH-Geohash
~~~

# Server Behavior

Upon receiving a Geohash Client Hint, a server can use the information to influence its behavior
in various ways.

The server can use the Geohash to determine the content of HTTP responses, as a
replacement for inferring location from client IP addresses.

If the server is acting as a forward proxy, such as a CONNECT proxy, it can use the Geohash
to determine an appropriate geo-mapped IP address to use for outbound connections, or a
client subnet to present in the EDNS0 Client Subnet extension for DNS queries {{?RFC6891}}
{{?RFC7871}}.

## Proxy Behavior

If a proxy receiving the Geohash hint cannot respect the location indicated by the hint,
it SHOULD include a Proxy-Status header {{!I-D.ietf-httpbis-proxy-status}} in its response,
with the "details" parameter containing the string "invalid geohash".

~~~
Proxy-Status: ExampleProxy; details="invalid geohash"
~~~

# Security Considerations {#security}

The use of the Geohash Client Hint MUST use the Sec- header prefix as recommended
in {{!RFC8942}}.

Client location can be used to fingerprint and tracker users, so clients MUST have a
default policy around when to allow use of the Geohash Client Hint, as well as a default
length of Geohash. Shorter, truncated Geohashes provide less specific locality.

Servers MUST NOT use Geohash Client Hints for making security or access-control decisions,
as the value can be spoofed by a client. The hint is intended only for use in optimizing behavior.

# IANA Considerations {#iana}

## HTTP Headers {#iana-header}

This document registers the "Sec-CH-Geohash" header in the
"Permanent Message Header Field Names" registry
<[](https://www.iana.org/assignments/message-headers)>.

~~~
  +----------------------+----------+--------+---------------+
  | Header Field Name    | Protocol | Status |   Reference   |
  +----------------------+----------+--------+---------------+
  | Sec-CH-Geohash       |   http   |  exp   | This document |
  +----------------------+----------+--------+---------------+
~~~
