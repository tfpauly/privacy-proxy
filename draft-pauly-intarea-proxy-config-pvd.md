---
title: Communicating Proxy Configurations in Provisioning Domains
abbrev: Proxy Configuration PvDs
docname: draft-pauly-intarea-proxy-config-pvd-latest
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

This document defines a mechanism for accessing provisioning domain information
associated with a proxy, such a list of DNS zones that are accessible via an HTTP
CONNECT proxy. It also defines a way to enumerate proxies that are associated with
a known provisioning domain.

--- middle

# Introduction

HTTP proxies that use the CONNECT method {{Section 9.3.6 of !HTTP=RFC9110}}
(often referred to as "forward" proxies) allow clients to open connections to
hosts via a proxy. These typically allow for TCP stream proxying, but can also support
UDP proxying {{!CONNECTUDP=RFC9298}} and IP packet proxying
{{!CONNECTIP=I-D.ietf-masque-connect-ip}}. Such proxies are not just defined as
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

This document defines two mechanisms to use PvDs to help clients understand how
to use proxies:

1. A way to fetch PvD Additional Information associated with a proxy URI, which
allows defining a limisted set of DNS zones that are accessible through the
proxy {{proxy-pvd}}.

1. A way to associate one or proxy URIs with a known PvD to allow clients to learn
about other proxies when they already know about a proxy PvD or network-provided
PvD {{proxy-enumeration}}.

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
on executing Javascript scripts, which can open up security vulnerabilities.

## Requirements

{::boilerplate bcp14}

# Accessing PvD Additional Information for proxies {#proxy-pvd}

This document defines a way to fetch PvD Additional Information associated with
a particular proxy resource. This PvD describes the properties of the network
accessible through the proxy.

## Fetching proxy PvDs

Some HTTP forward proxies, like those used for UDP and IP proxying, are identified
by URI templates that contains paths, such as
"https://proxy.example.org/masque{?target_host,target_port}". For such
cases, a client can fetch the PvD Additional Information by issuing a GET request
{{Section 9.3.1 of HTTP}} to the proxy URI, with template variables removed,
and setting the media type "application/pvd+json" {{PVDDATA}} in an Accept header.

For example, a client would issue the following request for the PvD associated
with "https://proxy.example.org/masque{?target_host,target_port}":

~~~
:method = GET
:scheme = https
:authority = proxy.example.org
:path = /masque
accept = application/pvd+json
~~~

CONNECT forward proxies that proxy TCP streams do not contain a path. For such cases,
a client can fetch the PvD Additional Information by issuing a GET request to the path
"/". For example:

~~~
:method = GET
:scheme = https
:authority = proxy.example.org
:path = /
accept = application/pvd+json
~~~

## Proxy PvD contents

PvD Additional Information is required to contain the "identifier", "expires", and
"prefixes" keys.

For proxy PvDs as defined in this document, the "identifier" MUST match the hostname
of the HTTP proxy. The "prefixes" array SHOULD be empty by default.

### Split DNS accessibility

Split DNS configurations are cases where only a subset of domains is routed through
a VPN tunnel or a proxy. For example, IKEv2 defines split DNS configuration in
{{?IKEV2SPLIT=RFC8598}}.

PvD Additional Information can be used to indicate that a proxy PvD has a split DNS
configuration.

{{Section 4.3 of PVDDATA}} defines the optional `dnsZones` key, which contains
searchable and accessible DNS zones as an array of strings.

When present in a PvD Additional Information dictionary that is retrieved using a GET
request to the proxy URI as described in {{proxy-pvd}}, domains in the `dnsZones`
array indicate specific zones that are accessible using the proxy. If a hostname is
not included in the enumerated zones, then a client SHOULD assume that the hostname
will not be accessible through the proxy.

Entries listed in `dnsZones` MUST NOT expand the set of domains that a client is
willing to send to a particular proxy. The list can only narrow the list of domains
that the client is willing to send through the proxy. For example, if the client
has a local policy to only send requests for "example.com" to a proxy
"proxy.example.com", and the `dnsZones` array contains "internal.example.com" and
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
:path = /masque
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
  "dnsZones": ["internal.example.org"]
}
~~~

The client could then choose to use this proxy only for accessing names that fall
within the "internal.example.org" zone.

# Enumerating proxies within a PvD {#proxy-enumeration}

PvD Additional Information can also be used to list proxies that
are associated with a particular PvD. This association represents
availability of a proxy, but does not indicate any policy of the PvD that
requires clients to use a proxy or not.

This document defines a new PvD Additional Information key, `proxies`, that
is an array of strings that is a list of proxy URIs (or URI templates
{{!URITEMPLATE=RFC6570}}). The new key is registered in {{iana}}.

The kind of proxy is implied by the URI scheme and any template variables.
For example, since UDP proxying {{CONNECTUDP}} has the URI template variables
`target_host` and `target_port`, the URI
"https://proxy.example.org:4443/masque{?target_host,target_port}" implies
that the proxy supports UDP proxying.

## Associating proxies with known proxies

When a PvD that contains the `proxies` key is fetched from a known proxy URI,
using the method described in {{proxy-pvd}}, the proxies list describes
equivalent proxies (potentially supporting other protocols) that can be used
in addition to the known proxy.

Such cases are useful for informing clients of related proxies as a discovery
method, with the assumption that the client already is aware of one proxy.

## Associating proxies with a PvD identifier

When a PvD that contains the `proxies` key is fetched from the well-known
PvD URI (".well-known/pvd"), the list allows enumeration of proxies
that apply to the entire PvD identifier. There are two use cases this can
support: configuring proxies from an FQDN and configuring proxies from a
network.

### Proxy configuration from a FQDN

Many historical methods of configuring a proxy only allow configuring
a single FQDN hostname for the proxy. A client can attempt to fetch the
PvD information from the well-known URI to learn the list of complete
URIs that support non-default protocols, such as {{CONNECTUDP}} and
{{CONNECTIP}}.

For example, if a user has configured a proxy with the name
"proxy.example.com", the client can fetch
"https://proxy.example.com/.well-known/pvd" to detect a list of
associated proxies.

### Network-specified proxies

{{PVDDATA}} defines how PvD Additional Information is discovered based
on network advertisements using Router Advertisements {{?RFC4861}}. A network
defining its configuration via PvD information can include the `proxies`
key to inform clients of a list of proxies available on the network.

Policy for whether or not clients use the proxies is implementation-specific
and might depend on other keys defined in the PvD Additional Information.

## Example

Given a known FQDN "company.example.org", which was discovered
from a PvD Router Advertisement option, a client could request PvD
additional information with the following request:

~~~
:method = GET
:scheme = https
:authority = company.example.org
:path = /.well-known/pvd
accept = application/pvd+json
~~~

If the proxy has a PvD definition for this FQDN, it could return the following
response to indicate a PvD that has two related proxy URIs.

~~~
:status = 200
content-type = application/pvd+json
content-length = 222

{
  "identifier": "company.example.org.",
  "expires": "2023-06-23T06:00:00Z",
  "prefixes": ["2001:db8:cafe::/48"],
  "proxies": ["https://proxy.example.org","https://proxy.example.org/masque{?target_host,target_port}"]
}
~~~

The client could then choose to use the available proxies, and could
look up the PvD Additional Information files on those URIs, depending on client
policy for using proxies.

# Security Considerations {#sec-considerations}

Configuration advertised via PvD Additional Information, such DNS zones or associated
proxies, can only be safely used when fetched over a secure TLS-protected connection,
and the client has validated that that the hostname of the proxy, the identifier of
the PvD, and the validated hostname identity on the certificate all match.

# IANA Considerations {#iana}

This document registers a new key in the "Additional Information PvD Keys" registry.

JSON Key: proxies

Description: Array of proxy URIs associated with this PvD

Type: Array of strings

Example: ["https://proxy.example.com", "https://proxy.example.com/masque{?target_host,tcp_port}"]
