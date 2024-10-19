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
 -
    ins: C. McMullin
    name: Ciara McMullin
    organization: Google LLC
    email: ciaramcmullin@google.com
 -
    ins: D. Mitchell
    name: Dustin Mitchell
    organization: Google LLC
    email: djmitche@gmail.com
--- abstract

Techniques that improve user privacy by hiding original client IP addresses,
such as VPNs and proxies, have faced challenges with server that rely on
IP addresses to determine client location. Maintaining a geographically
relevant user experience requires large pools of IP addresses, which can
be costly. Additionally, users often receive inaccurate geolocation
results because servers rely on geo-IP feeds that can be outdated. To
address these challenges, we can allow clients to actively send their
network geolocation directly to the origin server via an HTTP Client
Hint. This approach will not only enhance geolocation accuracy and reduce IP
costs, but it also gives clients more transparency regarding their perceived
geolocation.

--- middle

# Introduction {#introduction}

HTTP Client Hints {{!RFC8942}} defines a convention for HTTP headers to
communicate optional information from clients to servers as hints. This
can be done conditionally based on whether a server claims to support a
particular hint. A server can request hints by listing them in the
Accept-CH response header.

This document defines a client hint that can be used to send a
geolocation entry based on the client's determined location. This
location can be used to influence server behavior, such as by causing
the server to return responses relevant to the client's location. The
format of the geolocation hint is the same as that defined for IP
geolocation feeds in {{!GEOFEED=RFC8805}}. It only allows for
coarse-level location specification.

This header aims to provide rough geolocation hints to servers based on
the client’s network location, shifting geolocation from a passive
IP-based approach to an active client-controlled one. This not only
allows the client to influence how their location is interpreted, but
it also reduces the need for extensive IP address pools when clients
mask their IP addresses through VPNs or proxies. Typically, VPN or proxy
providers need to manage egress IPs for each region to maintain
accurate geolocation. With a client-provided location hint, the hint can
minimize the number of IP addresses needed while still supporting
location-specific content such as weather, local news, and search
results. In addition, the hint reduces most servers' reliance on geo-IP
feeds that often come with limitations such as outdated
IP-to-location mappings and ongoing maintenance costs.

The client determines geolocation via a cooperating server
that performs a geo-IP database lookup of the client's IP address.

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

Given that the Sec-CH-IP-Geo is a high-entropy client hint (i.e.,
a client hint that is not in the low-entropy hint table), the server
needs to explicitly opt-in in order to receive the Geo Client Hint as defined in
{{RFC8942}}. It will not be sent by default and the server MAY
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

The client MUST determine geolocation using a cooperating server
that looks up the client's IP address in a geo-IP database. The client
MUST NOT use GPS. The client hint value MUST NOT be more precise
or detailed than what can be inferred from the user’s IP address.
When the client is routing traffic through a proxy or a VPN, the
IP address used to generate this geolocation hint MUST be an
address that is presented upstream beyond the proxy or VPN
(in other words, the "egress IP address"). The proxy or VPN's
selection of this egress IP address MAY have been based on
the client's original un-proxied IP address, but any hints that
the client presents to servers beyond a proxy or VPN MUST NOT
reveal more geolocation information that would be possible to
determine from looking up information about the egress IP address
itself.

The client MAY include the client hint header in requests to the
server after the server has explicitly opted in to receiving the
hint, or if the client knows of specific server configurations,
such as proxy settings, that support including the hint.

# Server Behavior

Upon receiving a Geolocation Client Hint, a server can use the
information to influence its behavior in various ways, such as
determining the content of HTTP responses.

Servers can choose to use the hint value in one of several ways,
including:

- Using the client hint information instead of consulting IP-based
geolocation feeds.
- Recognizing a mismatch between the client hint information and the server's
current result from its IP-based geolocation feed as a reason to schedule an
automatic refresh of its geolocation feed information. This can help ensure that
changes to feeds are adopted quickly, improving results for clients that don't
send the client hint.
- Serving content that corresponds to the client’s indicated location,
including delivering region-specific news, weather forecasts, and
relevant advertisements.

The server MUST be able to handle situations where geolocation is
not provided in a request. Since not all web clients will send a
Geolocation Client Hint, the server MAY defer to alternative methods
such as IP-based geolocation feeds to provide said value.

# Security Considerations {#sec-considerations}

Servers MUST NOT use Geolocation Client Hints for security or
access-control decisions, as the value is provided by the client
without additional authentication or verification. Servers that
offer services restricted to clients in a specific country or
administrative region might already rely on geoIP databases to
determine the client's location for access control purposes.
However, the Geolocation Client Hint can be used to customize
responses based on where the client claims to be within that
restricted region.

# Privacy Considerations {#privacy}

Any value provided in this hint MUST NOT be more specific than the
information that could be obtained from the client's IP address and
a well-maintained map of IP ranges to locations. In particular,
when a privacy technology such as a VPN is in use, the value MUST
NOT reveal information about the user's location that would
otherwise be hidden.

To prevent disclosing private information, this value cannot be
based on other sources of geolocation data, such as GPS or physical
latitude and longitude coordinates. Providing overly precise location
information could expose sensitive user information especially when
combined with other identifiable signals. Furthermore, when a client
designates a location different from that derived from their IP
address, the combination of designated location and IP can create a
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
