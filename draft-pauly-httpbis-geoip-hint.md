---
title: The IP Geolocation HTTP Client Hint
abbrev: Geohash CH
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

This documents defines an HTTP Client Hint that allows a client to share information
about its IP Geolocation. This helps ensure that servers have information about location
that is consistent with what a client expects and what other servers use.

--- middle

# Introduction {#introduction}

HTTP Client Hints {{!RFC8942}} defines a convention for HTTP headers
to communicate optional information from clients to servers as hints. This can be done
conditionally based on if a server claims supports for a particular hint.

This document defines a client hint that can be used to send a IP geolocation entry that
maps to the client's IP address. This location can be used to influence server behavior,
such as by causing the server to return responses relevant to the client's location.
The format of the IP geolocation entry is the same as that defined for IP geolocation
feeds in {{!GEOFEED=RFC8805}}.

This header is intended to be used to provide rough geolocation hints to servers that do
not already have accurate or authoritative mappings for the IP addresses of clients. This
can be particularly useful for cases where IP geolocation mappings have changed recently,
or a client is using a VPN or proxy that may not be commonly recognized by servers.

The mechanism for how a client learns the IP geolocation mapping to send is beyond the
scope of this document. {{?RFC9092}} defines some mechanisms for discovery, but clients
can also have other mechanisms (such as coordinating with a VPN or proxy that is assigning
the client a tunnelled or proxied address) to learn what hint to sent.

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

This field also defines a parameter, "feed", that contains the URI of the
IP geolocation feed that is authoritative for this entry. For example:

~~~
    Sec-CH-IP-Geo = "SG,SG-01,Singapore"; feed="https://noc.ietf.org/geo/google.csv"
~~~

Servers that can provide different content based on Geohash hints SHOULD include
the headers in their "Accept-CH" list.

~~~
    Accept-CH: Sec-CH-IP-Geo
~~~

Servers also SHOULD indicate for any cacheable content if the IP geo hints will influence
the cached content, using the "Vary" header.

~~~
    Vary: Sec-CH-IP-Geo
~~~

# Server Behavior

Upon receiving a IP Geolocation Client Hint, a server can use the information to influence
its behavior in various ways, such as determining the content of HTTP responses.

Many servers have existing IP geolocation feeds that they use to identify client locations.
Servers can choose to use the hint value in one of several ways:

- Use the client hint information instead of consulting another geolocation feed.
- Check the value of the "feed" parameter on the header and determine if it is a trusted feed.
   If this feed is trusted, but is not the default feed used by the server, the server
   can choose to prefer the feed indicated by the client.
- Check the value of the "feed" parameter on the header and fetch a copy of the feed
   to verify the mapping, if a copy of the feed has not been fetched recently.
- If the feed indicated in the "feed" parameter is unknown or untrusted, but starts
   becoming common, the server can flag this feed as one to be manually checked and
   added, if appropriate. This allows servers to automatically discover when new
   feeds and services are brought up..

If the server is acting as a forward proxy, such as a CONNECT proxy, it can use the hint
to determine an appropriate geo-mapped IP address to use for outbound connections, or a
client subnet to present in the EDNS0 Client Subnet extension for DNS queries {{?RFC6891}}
{{?RFC7871}}.

# Security Considerations {#security}

The use of the IP Geolocation Client Hint MUST use the Sec- header prefix as recommended
in {{!RFC8942}}.

Servers MUST NOT use IP Geolocation Client Hints for making security or access-control decisions,
as the value can be spoofed by a client. The hint is intended only for use in optimizing behavior.

The value contained in this hint SHOULD be based only on a IP Geolocation feed value for
an IP address the client is already presenting to a server. In order to avoid disclosing
any private information, this value MUST not be based on geolocation of the client determined
by other means, such as physical latitude and longitude coordinates.

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
