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
to only allow access to a limited set of next hops.

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

1. A way to define a limited set of DNS zones that are accessible through the
proxy ({{split-dns}}).

Additionally, this document partly describes how these mechanisms might be used
to discover proxies associated with a network ({{network-proxies}}).

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
`proxies` array, `protocol` and `proxy`. There are also optional key, including
`alpn`, and keys for split-DNS defined in {{split-dns}}.
Other optional keys can be added to the dictionary
to further define or restrict the use of a proxy. Clients that do not
recognize or understand a key in a proxy sub-dictionary MUST ignore the entire
proxy definition, since the proxy might be only applicable for particular
uses. These keys are registered in an IANA registry, defined in {{proxy-info-iana}}.

| JSON Key | Optional | Description | Type | Example |
| --- | --- | --- | --- | --- |
| protocol | No | The protocol used to communicate with the proxy | String | "connect-udp" |
| proxy | No | String containing the URI template or hostname and port of the proxy, depending on the format defined by the protocol | String | "https://proxy.example.org:4443/masque{?target_host,target_port}" |
| alpn | Yes | An array of Application-Layer Protocol Negotiation protocol identifiers | Array of Strings | ["h3","h2"] |

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

# Split DNS information for proxies {#split-dns}

Split DNS configurations are cases where only a subset of domains is routed through
a VPN tunnel or a proxy. For example, IKEv2 defines split DNS configuration in
{{?IKEV2SPLIT=RFC8598}}.

PvD Additional Information can be used to indicate that a proxy PvD has a split DNS
configuration.

This document defines two optional keys that for subdictionaries in the `proxies`
array that are used for split-DNS configuration.

| JSON Key | Optional | Description | Type | Example |
| --- | --- | --- | --- | --- |
| matchDomains | Yes | An array of DNS zones or subdomains that can be accessed over this proxy | Array of Strings | [ "example.com" ] |
| excludeDomains | Yes | An array of DNS zones or subdomains that cannot be accessed over this proxy. If matchDomains is specfied, excludeDomains should list more specific domains within entries in the matchDomains array | Array of Strings | [ "public.example.com" ] |

When present in a PvD Additional Information dictionary that is retrieved for a proxy
as described in {{proxy-pvd}}, domains in the `matchDomains` array indicate specific zones
that are accessible using the proxy. If a hostname is not included in the enumerated
zones, then a client SHOULD assume that the hostname will not be accessible through the
proxy. If a hostname is included in the `excludeDomains` array, then the client SHOULD NOT
access it through the proxy. The `excludeDomains` parameter can be present even if `matchDomains`
is omitted. When this is the case, the client assumes that all domains except the domains
listed in the `excludeDomains` array are accessible through the proxy.

Entries listed in `matchDomains` MUST NOT expand the set of domains that a client is
willing to send to a particular proxy. The list can only narrow the list of domains
that the client is willing to send through the proxy. For example, if the client
has a local policy to only send requests for "example.com" to a proxy
"proxy.example.com", and the `matchDomains` array contains "internal.example.com" and
"other.company.com", the client would end up only proxying "internal.example.com"
through the proxy.

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
response to indicate a PvD that has one accessible zone, "internal.example.org".

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
      "matchDomains": [ "internal.example.org" ]
    }
  ]
}
~~~

The client could then choose to use this proxy only for accessing names that fall
within the "internal.example.org" zone.

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
The initial contents of this registry are given in {{proxy-enumeration}} and {{split-dns}}.

New assignments in the "Proxy Information PvD Keys" registry will be administered by IANA through Expert Review {{!RFC8126}}. Experts are
requested to ensure that defined keys do not overlap in names or semantics.

## New PvD Proxy Protocol Registry {#proxy-protocol-iana}

IANA is requested to create a new registry "Proxy Protocol PvD Values", within the "Provisioning Domains (PvDs)" registry page.
This new registry reserves JSON values for the `protocol` key in `proxies` sub-dictionaries.
The initial contents of this registry are given in {{proxy-enumeration}}.

New assignments in the "Proxy Protocol PvD Values" registry will be administered by IANA through Expert Review {{!RFC8126}}.
Experts are requested to ensure that defined keys do not overlap in names or semantics, and have clear format definitions.
The reference and notes fields MAY be empty.
