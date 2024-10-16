---
title: The IP Geolocation HTTP Client Hint
abbrev: IP-Geo Client Hint
docname: draft-pauly-httpbis-geoip-hint-latest
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
 -
    ins: D. Schinazi
    name: David Schinazi
    organization: Google LLC
    email: dschinazi.ietf@gmail.com

--- abstract

This document defines an HTTP Client Hint that allows the client to
share its location, reducing the need for destination servers to map IP
ranges to locations. By actively providing their location, clients gain
greater influence and transparency regarding their geolocation.
Additionally, when IP-hiding technologies like VPNs or proxies are
used, servers can still deliver geographically relevant experiences
without relying on large IP address pools to cover regional areas or
costly third-party GeoFeeds, which can be outdated and inaccurate at
times.

--- middle

# Introduction {#introduction}

HTTP Client Hints {{!RFC8942}} defines a convention for HTTP headers to
communicate optional information from clients to servers as hints. This
can be done conditionally based on if a server claims to support a
particular hint. A server requests hints by listing them in the
Accept-CH response header, or via other methods such as ALPS or
ACCEPT_CH frames.

This document defines a client hint that can be used to send a
geolocation entry based on the client's determined location. This
location can be used to influence server behavior, such as by causing
the server to return responses relevant to the client's location. The
format of the geolocation entry is the same as that defined for IP
geolocation feeds in {{!GEOFEED=RFC8805}}. It only allows for
coarse-level location specification.

This header aims to provide rough geolocation hints to servers based on
the client’s determined location, shifting geolocation from a passive
IP-based approach to an active client-controlled one. This not only
allows the client to influence how their location is interpreted, but
it also reduces the need for extensive IP address pools when clients
mask their IP addresses through VPNs or proxies. Typically, VPN
providers need to purchase egress IPs for each region to maintain
accurate geolocation. With client-determined location, the hint can
minimize the number of IP addresses needed while still supporting
location-based services such as weather, local news, and search
results. In addition, the hint reduces reliance on third-party
GeoFeeds which often come with limitations such as outdated
IP-to-location mappings and ongoing maintenance costs.

The mechanism by which the client determines its geolocation is beyond
the scope of this document. However, the geolocation should still be
derived from the IP address.

This draft doesn’t eliminate the need for IP Geolocation, but adds an
additional source of information for many use cases. See [Security
Considerations] for more discussion.

## Requirements

{::boilerplate bcp14}

# IP Geo Header

The "Sec-CH-IP-Geo" is an Item Structured Field {{!STRUCTURED-FIELDS=RFC8941}}.
The field's value is a String. The string uses the format defined in
{{Section 2.1.1 of GEOFEED}}, with the IP Prefix element removed. Thus, this
contains a comma-separated list of Alpha2code, Region, and City. The
value SHOULD NOT contain a Postal Code.

For example, the header for an entry "192.0.2.5,US,US-AL,Alabaster" would be:

~~~
    Sec-CH-IP-Geo = "US,US-AL,Alabaster"
~~~

Given that the Sec-CH-IP-Geo is a high-entropy client hint, meaning it is
a client hint that is not in the low-entropy hint table, the server
MUST explicitly opt-in to receive the Geo Client Hint as defined in
{{?RFC8942}}. It will not be sent by default and the server MAY
indicate support for this hint via the Accept-CH header in the
initial response:

~~~
    Accept-CH: Sec-CH-IP-Geo
~~~

Servers SHOULD indicate for any cacheable content if the geo hints
will influence the cached content, using the 'Vary' header. This will
indicate that the server may have used this header as a determining
factor when choosing a response:

~~~
    Vary: Sec-CH-IP-Geo
~~~

# Client Behavior

If possible, the client SHOULD specify their geolocation. If location
is not available, the client MAY send a default value or none at all.
How the default value is determined is outside the scope of this
document. However, the default value MUST NOT be more precise or
detailed than what could be inferred from the user’s IP address.

The client MAY include the client hint in requests to the server after
the server has explicitly opted in to receiving the hint, or if the
client knows of specific server configurations, such as proxy
settings, that support including the hint.

# Server Behavior

Upon receiving a Geolocation Client Hint, a server can use the
information to influence its behavior in various ways, such as
determining the content of HTTP responses.

Servers can choose to use the hint value in one of several ways,
including:

- Using the client hint information instead of consulting IP-based
geolocation feeds.
- Serving content that corresponds to the client’s indicated location,
including delivering region-specific news, weather forecasts, and
relevant advertisements.
- Determining service availability and feature access based on the
client’s indicated location.

The server MUST be able to handle situations where geolocation is
not provided in a request. Since not all web clients, such as curl,
will send a Geolocation Client, the server MAY defer to alternative
methods such as IP-based geolocation feeds to provide said value.

If the server is acting as a forward proxy, such as a CONNECT proxy,
it can use the hint to determine an appropriate geo-mapped IP address
to use for outbound connections, or a client subnet to present in the
EDNS0 Client Subnet extension for DNS queries {{?RFC6891}}
{{?RFC7871}}.

# Security Considerations {#sec-considerations}

The use of the Geolocation Client Hint MUST use the Sec- header
prefix as recommended in {{!RFC8942}}.

Servers MUST NOT use Geolocation Client Hints for making security or
access-control decisions, as the value is provided by the client with
no additional authentication. The hint is intended only to be used
for greater user visibility and say over their geolocation.

# Privacy Considerations {#privacy}

Any default value provided in this hint MUST NOT be more specific than
the information that could be obtained from the client's IP address
and a well-maintained map of IP ranges to locations. In particular,
when a privacy technology such as a VPN is in use, the default value
MUST NOT reveal information about the user's location that would
otherwise be hidden.

To prevent disclosing private information, this value MUST NOT be
based on other sources of geolocation data, such as physical latitude
and longitude coordinates. Providing overly precise location
information could expose sensitive user information especially when
combined with other identifiable signals. Furthermore, when a client
designates a location different from that derived from their IP
address, the combination of designated location and IP may create a
unique identifier, increasing the risk of cross-site tracking.

The hint MUST NOT be sent by default or in an always-on manner. It
should only be included in response to explicit server requests (e.g.,
via the Accept-CH header) and in contexts where sharing location
data serves a clear purpose, such as for location-based services.

# IANA Considerations {#iana}

## HTTP Headers {#iana-header}

This document registers the "Sec-CH-IP-Geo" header in the
"Permanent Message Header Field Names" registry
<[](https://www.iana.org/assignments/message-headers)>.

~~~
  +----------------------+----------+--------+---------------+
  | Header Field Name    | Protocol | Status |   Reference   |
  +----------------------+----------+--------+---------------+
  | Sec-CH-IP-Geo        |   http   |  exp   | This document |
  +----------------------+----------+--------+---------------+
~~~
