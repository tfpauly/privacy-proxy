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

HTTP Client Hints {{!I-D.ietf-httpbis-client-hints}} defines a convention for HTTP headers
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

## Requirements

{::boilerplate bcp14}

# Geohash Header

The "Sec-CH-Geohash" and "Server-Connection-Id" are Item Structured
Headers {{!I-D.ietf-httpbis-header-structure}}. Its value MUST be a
String, and MUST have at least 1 character and no more than 12 characters.
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

# Security Considerations {#security}

The use of the Geohash Client Hint MUST use the Sec- header prefix as recommended
in {{!I-D.ietf-httpbis-client-hints}}.

Client location can be used to fingerprint and tracker users, so clients MUST have a
default policy around when to allow use of the Geohash Client Hint, as well as a default
length of Geohash. Shorter, truncated Geohashes provide less specific locality.

# IANA Considerations {#iana}

## HTTP Headers {#iana-header}

This document registers the "Sec-CH-Geohash" header in the
"Permanent Message Header Field Names"
<[](https://www.iana.org/assignments/message-headers)>.

~~~
  +----------------------+----------+--------+---------------+
  | Header Field Name    | Protocol | Status |   Reference   |
  +----------------------+----------+--------+---------------+
  | Sec-CH-Geohash       |   http   |  exp   | This document |
  +----------------------+----------+--------+---------------+
~~~
