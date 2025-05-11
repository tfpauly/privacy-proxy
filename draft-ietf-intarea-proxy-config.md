---
title: Communicating Proxy Configurations in Provisioning Domains
abbrev: Proxy Configuration PvDs
docname: draft-ietf-intarea-proxy-config-latest
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
    ins: D. Damjanovic
    name: Dragana Damjanovic
    org: Microsoft
    email: ddamjanovic@microsoft.com
 -
    ins: Y. Rosomakho
    fullname: Yaroslav Rosomakho
    organization: Zscaler
    email: yrosomakho@zscaler.com

--- abstract

This document defines a mechanism for accessing provisioning domain information
associated with a proxy, such as other proxy URIs that support different protocols
and a list of DNS zones that are accessible via a proxy.

--- middle

# Introduction

HTTP proxies that use the CONNECT method {{Section 9.3.6 of !HTTP=RFC9110}}
(often referred to as "forward" proxies) allow clients to open connections to
hosts via a proxy. These typically allow for TCP stream proxying, but can also support
UDP proxying {{!CONNECT-UDP=RFC9298}} and IP packet proxying
{{!CONNECT-IP=RFC9484}}. Such proxies are not just defined as
hostnames and ports, but can use URI templates {{!URITEMPLATE=RFC6570}}.

In order to make use of multiple related proxies, clients need a way to understand
which proxies are associated with one another.

Client can also benefit from learning about additional information associated with
the proxy to optimize their proxy usage, such knowing that a proxy is configured
to only allow access to a limited set of destinations.

These improvements to client behavior can be achieved through the use of
Provisioning Domains. Provisioning Domains (PvDs) are defined in {{?PVD=RFC7556}}
as consistent sets of network configuration information, which can include proxy
configuration details {{Section 2 of PVD}}. {{!PVDDATA=RFC8801}} defines a JSON
{{!JSON=RFC8259}} format for describing Provisioning Domain Additional Information,
which is an extensible dictionary of properties of the Provisioning Domain.

This document defines several mechanisms to use PvDs to help clients understand how
to use proxies:

1. A way to fetch PvD Additional Information associated with a known proxy URI ({{proxy-pvd}})

1. A way to list one or more proxy URIs in a PvD, allowing clients to
learn about other proxy options given a known proxy ({{proxy-enumeration}}).

1. A way to define a limited set of destinations that are accessible through the
proxy ({{destinations}}).

Additionally, this document partly describes how these mechanisms might be used
to discover proxies associated with a network ({{network-proxies}}).

Using this mechanism a client can learn that a legacy insecure HTTP proxy that
the client is configured with is also accessible using HTTPS. In this way,
clients can upgrade to a more secure connection to the proxy.

## Background

Other non-standard mechanisms for proxy configuration and discovery have been
used historically, some of which are described in {{?RFC3040}}.

Proxy Auto Configuration (PAC) files {{Section 6.2 of RFC3040}} are Javascript
scripts that take URLs as input and provide an output of a proxy configuration
to use.

Web Proxy Auto-Discovery Protocol (WPAD) {{Section 6.4 of RFC3040}} allows
networks to advertise proxies to use by advertising a PAC file. This solution
squats on DHCP option 252.

These common (but non-standard) mechanisms only support defining proxies by
hostname and port, and do not support configuring a full URI template
{{URITEMPLATE}}.

The mechanisms defined in this document are intended to offer a standard
alternative that works for URI-based proxies and avoids dependencies
on executing Javascript scripts, which are prone to implementation-specific
inconsistencies and can open up security vulnerabilities.

## Requirements

{::boilerplate bcp14}

# Fetching PvD Additional Information for proxies {#proxy-pvd}

This document defines a way to fetch PvD Additional Information associated with
a proxy. This PvD describes the properties of the network accessible through the proxy.

In order to fetch PvD Additional Information associated with a proxy, a client
issues an HTTP GET request for the well-known PvD URI (".well-known/pvd") {{PVDDATA}}
and the host authority of the proxy. This is applicable for both proxies that are identified
by a host and port only (such as SOCKS proxies and HTTP CONNECT proxies) and proxies
that are identified by a URI or URI template.

For example, a client would issue the following request for the PvD associated
with "https://proxy.example.org/masque{?target_host,target_port}":

~~~
:method = GET
:scheme = https
:authority = proxy.example.org
:path = /.well-known/pvd
accept = application/pvd+json
~~~

For a HTTP CONNECT proxy on "proxy.example.org:8080", the client would send the following
request:

~~~
:method = GET
:scheme = https
:authority = proxy.example.org:8080
:path = /.well-known/pvd
accept = application/pvd+json
~~~

Note that all proxies that are colocated on the same host and port share the same PvD
Additional Information. Proxy deployments that need separate PvD configuration properties
SHOULD use different hosts.

PvD Additional Information is required to contain the "identifier", "expires", and
"prefixes" keys. For proxy PvDs as defined in this document, the "identifier" MUST
match the hostname of the HTTP proxy. The "prefixes" array SHOULD be empty by default.

# Enumerating proxies within a PvD {#proxy-enumeration}

This document defines a new PvD Additional Information key, `proxies`, that
is an array of dictionaries, where each dictionary in the array defines
a single proxy that is available as part of the PvD (see {{proxies-key-iana}}).
Each proxy is defined by a proxy protocol, a proxy location (i.e., a hostname and port or a URI template
{{!URITEMPLATE=RFC6570}}), along with potentially other keys.

This document defines two mandatory keys for the sub-dictionaries in the
`proxies` array, `protocol` and `proxy`. There are also optional keys, including
`alpn`, `mandatory`, and destination accessibility keys defined in {{destinations}}.
Other optional keys can be added to the dictionary to further define or restrict the
use of a proxy.

| JSON Key | Optional | Description | Type | Example |
| --- | --- | --- | --- | --- |
| protocol | No | The protocol used to communicate with the proxy | String | "connect-udp" |
| proxy | No | String containing the URI template or hostname and port of the proxy, depending on the format defined by the protocol | String | "https://proxy.example.org:4443/masque{?target_host,target_port}" |
| alpn | Yes | An array of Application-Layer Protocol Negotiation protocol identifiers | Array of Strings | ["h3","h2"] |
| mandatory | Yes | An array of optional keys that client must understand and process to use this proxy | Array of Strings | ["match"] |

The values for the `protocol` key are defined in the proxy protocol
registry ({{proxy-protocol-iana}}), with the initial contents provided below.
For consistency, any new proxy types that use HTTP Upgrade Tokens (and use
the `:protocol` pseudo-header) SHOULD define the `protocol` value to match
the Upgrade Token / `:protocol` value.

| Proxy Protocol | Proxy Location Format | Reference | Notes |
| --- | --- | --- |
| socks5 | hostname:port | {{!SOCKSv5=RFC1928}} | |
| http-connect | hostname:port | {{Section 9.3.6 of HTTP}} | Standard CONNECT method, using unencrypted HTTP to the proxy |
| https-connect | hostname:port | {{Section 9.3.6 of HTTP}} | Standard CONNECT method, using TLS-protected HTTP to the proxy |
| connect-udp | URI template | {{CONNECT-UDP}} | |
| connect-ip | URI template | {{CONNECT-IP}} | |
| connect-tcp | URI template | {{!CONNECT-TCP=I-D.ietf-httpbis-connect-tcp}} | |

The value of `proxy` depends on the Proxy Location Format defined by proxy protocol.
The types defined here either use a hostname and port, or a full URI template.

If the `alpn` key is present, it provides a hint for the Application-Layer Protocol Negotiation
(ALPN) {{!ALPN=RFC7301}} protocol identifiers associated with this server. For HTTP proxies,
this can indicate if the proxy supports HTTP/3, HTTP/2, etc.

The value of the `mandatory` key is a list of keys that the client must understand and process to be
able to use the proxy. A client that does not understand a key from the list or cannot fully process
the value of a key from the list MUST ignore the entire proxy definition. The list can contain
only keys that are registered in an IANA registry, defined in {{proxy-info-iana}} and that are marked
as optional.  The `mandatory` list MUST NOT include any entries that are not present in the sub-dictionary.

When a PvD that contains the `proxies` key is fetched from a known proxy
using the method described in {{proxy-pvd}} the proxies list describes
equivalent proxies (potentially supporting other protocols) that can be used
in addition to the known proxy.

Such cases are useful for informing clients of related proxies as a discovery
method, with the assumption that the client already is aware of one proxy.
Many historical methods of configuring a proxy only allow configuring
a single FQDN hostname for the proxy. A client can attempt to fetch the
PvD information from the well-known URI to learn the list of complete
URIs that support non-default protocols, such as {{CONNECT-UDP}} and
{{CONNECT-IP}}.

## Proprietary Keys in Proxy Definitions {#proxy-proprietary-keys}

Implementations MAY include proprietary or vendor-specific keys in the sub-dictionaries of the `proxies`
array to convey additional proxy configuration information not defined in this specification.

A proprietary key MUST contain exactly one underscore character ("_"). This character serves as a
separator between the key name and a vendor-specific namespace. For example, "authmode_acme" could
be a proprietary key indicating an authentication mode defined by vendor acme.

Clients that encounter a proprietary key they do not recognise MUST apply the following logic:

- If the key appears in the `mandatory` array of the proxy definition, the client MUST ignore the entire proxy entry.
- If the key is not listed in the `mandatory` array, the client MUST ignore the unrecognised proprietary key and proceed with processing the proxy definition as usual.

This mechanism allows implementations to extend proxy metadata while maintaining interoperability and ensuring safe fallback behaviour for clients that do not support a given extension.

## Example

Given a known HTTP CONNECT proxy FQDN, "proxy.example.org", a client could
request PvD Additional Information with the following request:

~~~
:method = GET
:scheme = https
:authority = proxy.example.org
:path = /.well-known/pvd
accept = application/pvd+json
~~~

If the proxy has a PvD definition for this FQDN, it would return the following
response to indicate a PvD that has two related proxy URIs.

~~~
:status = 200
content-type = application/pvd+json
content-length = 222

{
  "identifier": "proxy.example.org.",
  "expires": "2023-06-23T06:00:00Z",
  "prefixes": [],
  "proxies": [
    {
      "protocol": "http-connect",
      "proxy": "proxy.example.org:80"
    },
    {
      "protocol": "connect-udp",
      "proxy": "https://proxy.example.org/masque{?target_host,target_port}"
    }
  ]
}
~~~

The client would learn the URI template of the proxy that supports UDP using {{CONNECT-UDP}},
at "https://proxy.example.org/masque{?target_host,target_port}".

# Destination accessibility information for proxies {#destinations}

Destination accessibility information is used when only a subset of destinations is reachable through
a proxy. Destination restrictions are often used in VPN tunnel configurations such as split
DNS in IKEv2 {{?IKEV2SPLIT=RFC8598}}.

PvD Additional Information can be used to indicate that a proxy PvD only allows access to a limited
set of destinations.

This document defines two optional keys for subdictionaries in the `proxies`
array that are used to signal information about destinations available through the proxy.

| JSON Key | Optional | Description | Type |
| --- | --- | --- | --- |
| match | Yes | An array of destination objects defining targets accessible over this proxy | Array of Objects |
| exclude | Yes | An array of destination objects defining targets that cannot be accessed over this proxy | Array of Objects |

This document defined three keys for destination objects. A destination object cannot
be empty and MUST contain at least one valid key. Each provided key MUST correspond to an array with at least one entry.

| JSON Key | Description | Type | Example |
| --- | --- | --- | --- |
| domains | An array of FQDNs and wildcard DNS domains | Array of Strings | ["www.example.com", "*.internal.example.com"] |
| subnets | An array of IPv4 and IPv6 addresses and subnets | Array of Strings | ["2001:DB8::1", "192.168.1.0/24"] |
| ports | An array of TCP and UDP port ranges | Array of Strings | ["80", "443", "1024-65535"] |

When present in a PvD Additional Information dictionary that is retrieved for a proxy
as described in {{proxy-pvd}}, entries in the `domains` array of a `match` object indicate
specific FQDNs and zones that are accessible using the proxy. If a hostname does not match any entry,
then a client SHOULD assume that the hostname will not be accessible through the proxy.
If a hostname is included in the `domains` array of an `exclude` object, then the client SHOULD NOT
access it through the proxy. The `domains` array can be present in an `exclude` object even if `domains`
is omitted from all `match` objects or `match` key is not present in the `proxies` array subdictionary.
When this is the case, the client assumes that all domains except the domains
listed in the `domains` from `exclude` objects are accessible through the proxy. If `domains` arrays are
specified in `match` and `exclude` objects, `domains` arrays from `exclude` objects SHOULD
list more specific domains within entries in `domains` arrays from `match` objects.

A wildcard prefix (`*.`) is used to indicate matching entire domains or subdomains instead of specific hostnames. Note
that this can be used to match multiple levels of subdomains. For example "*.example.com"
matches "internal.example.com" as well as "www.public.example.com".
Entries that include the wildcard prefix also SHOULD be treated as if they match
an FQDN that only contains the string after the prefix, with no subdomain. So,
an entry "*.example.com" in the `domains` array of a `match` object would match the FQDN "example.com",
unless "example.com" was specifically included in the `domains` array of an `exclude` object. This is
done to prevent commonly needing to include both "*.example.com" and "example.com"
in the `domains` array of a `match` object.

Entries in `subnets` array of a `match` object correspond to IP addresses and subnets that are available through the
proxy, while entries in `subnets` array of an `exclude` object define IP addresses and subnets that SHOULD NOT be used
with the proxy. Subnet-based destination information SHOULD only be used when
applications are communicating with destinations identified by only an IP address and not a hostname.
If `subnets` arrays are specified in `match` and `exclude` objects, `subnets` arrays from `exclude` objects SHOULD
list more specific subnets within entries in `subnets` arrays from `match` objects.

Port specification, if provided, refines the criteria for domain or subnet matching.
For example, `ports` array of ["80", "443"] together with `domains` array of ["www.example.com"]
in a `match` object specifies that only ports 80 and 443 of "www.example.com"
domain are accessible through the proxy. If `ports` key is not present in a `match` or `exclude` object,
all ports are assumed to match. Comma-separated port list may contain individual port numbers (such as "80")
or inclusive ranges of ports. For example "1024-2048" matches all ports from 1024 to 2048, including the 1024 and 1028.

Entries listed in a `match` object MUST NOT expand the set of destinations that a client is
willing to send to a particular proxy. The list can only narrow the list of destinations
that the client is willing to send through the proxy. For example, if the client
has a local policy to only send requests for "*.example.com" to a proxy
"proxy.example.com", and `domains` array of a `match` object contains "internal.example.com" and
"other.company.com", the client would end up only proxying "internal.example.com"
through the proxy.

## Proprietary Keys in Destination Rules

Implementations MAY include proprietary or vendor-specific keys in destination rules to define custom matching logic
not specified in this document.

Similarly to proprietary keys in proxy definitions ({{proxy-proprietary-keys}}), a proprietary key in destination
rule MUST contain exactly one underscore character ("_"), which separates the key name from a vendor-specific namespace.
For example, "processid_acme" could be a key used to apply rules only to traffic of a specific process identifier as
defined by vendor acme.

Clients that encounter a proprietary key they do not recognise MUST ignore the entire destination rule in which the
key appears. This ensures that unknown or unsupported matching logic does not inadvertently influence proxy selection
or bypass security controls. This handling applies uniformly across all match rules, including fallback rules.

## Example

Given a proxy URI template "https://proxy.example.org/masque{?target_host,target_port}",
which in this case is for UDP proxying, the client could request PvD additional information
with the following request:

~~~
:method = GET
:scheme = https
:authority = proxy.example.org
:path = /.well-known/pvd
accept = application/pvd+json
~~~

If the proxy has a PvD definition for this proxy, it could return the following
response to indicate a PvD that has one accessible zone, "*.internal.example.org".

~~~
:status = 200
content-type = application/pvd+json
content-length = 135

{
  "identifier": "proxy.example.org.",
  "expires": "2023-06-23T06:00:00Z",
  "prefixes": [],
  "proxies": [
    {
      "protocol": "http-connect",
      "proxy": "proxy.example.org:80"
    },
    {
      "protocol": "connect-udp",
      "proxy": "https://proxy.example.org/masque{?target_host,target_port}",
      "match": [{
        domains: [ "*.internal.example.org" ]
      }]
    }
  ]
}
~~~

The client could then choose to use this proxy only for accessing names that fall
within the "*.internal.example.org" zone.

# Discovering proxies from network PvDs {#network-proxies}

{{PVDDATA}} defines how PvD Additional Information is discovered based
on network advertisements using Router Advertisements {{?RFC4861}}. A network
defining its configuration via PvD information can include the `proxies`
key ({{proxy-enumeration}}) to inform clients of a list of proxies available
on the network.

This association of proxies with the network's PvD can be used as a mechanism
to discover proxies, as an alternative to PAC files. However, client systems MUST
NOT automatically send traffic over proxies advertised in this way without
explicit configuration, policy, or user permission. For example, a client
can use this mechanism to choose between known proxies, such as if the client was
already proxying traffic and has multiple options to choose between.

Further security and experience considerations are needed for these cases.

# Security Considerations {#sec-considerations}

Configuration advertised via PvD Additional Information, such DNS zones or associated
proxies, can only be safely used when fetched over a secure TLS-protected connection,
and the client has validated that that the hostname of the proxy, the identifier of
the PvD, and the validated hostname identity on the certificate all match.

# IANA Considerations

## New PvD Additional Information key {#proxies-key-iana}

This document registers a new key in the "Additional Information PvD Keys" registry.

JSON Key: proxies

Description: Array of proxy dictionaries associated with this PvD

Type: Array of dictionaries

Example: [ {
  "protocol": "connect-udp",
  "proxy": "https://proxy.example.org/masque{?target_host,target_port}"
} ]

## New PvD Proxy Information Registry {#proxy-info-iana}

IANA is requested to create a new registry "Proxy Information PvD Keys", within the "Provisioning Domains (PvDs)" registry page.
This new registry reserves JSON keys for use in sub-dictionaries under the `proxies` key.
The initial contents of this registry are given in {{proxy-enumeration}} and {{destinations}}.

New assignments in the "Proxy Information PvD Keys" registry will be administered by IANA through Expert Review {{!RFC8126}}. Experts are
requested to ensure that defined keys do not overlap in names or semantics.

## New PvD Proxy Protocol Registry {#proxy-protocol-iana}

IANA is requested to create a new registry "Proxy Protocol PvD Values", within the "Provisioning Domains (PvDs)" registry page.
This new registry reserves JSON values for the `protocol` key in `proxies` sub-dictionaries.
The initial contents of this registry are given in {{proxy-enumeration}}.

New assignments in the "Proxy Protocol PvD Values" registry will be administered by IANA through Expert Review {{!RFC8126}}.
Experts are requested to ensure that defined keys do not overlap in names or semantics, and have clear format definitions.
The reference and notes fields MAY be empty.
