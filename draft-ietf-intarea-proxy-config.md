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
and information about which destinations are accessible using a proxy.

--- middle

# Introduction

HTTP proxies that use the CONNECT method defined in {{Section 9.3.6 of !HTTP=RFC9110}}
(often referred to as "forward" proxies) allow clients to open connections to
hosts via a proxy. These typically allow for TCP stream proxying, but can also support
UDP proxying {{!CONNECT-UDP=RFC9298}} and IP packet proxying
{{!CONNECT-IP=RFC9484}}. The locations of these proxies are not just defined as
hostnames and ports, but can use URI templates {{!URITEMPLATE=RFC6570}}.

In order to make use of multiple related proxies, clients need a way to understand
which proxies are associated with one another, and which protocols can be used
to communicate with the proxies.

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

1. A way to define the set of destinations that are accessible through the
proxy ({{destinations}}).

Additionally, this document partly describes how these mechanisms might be used
to discover proxies associated with a network ({{network-proxies}}).

Using this mechanism a client can learn that a legacy insecure HTTP proxy that
the client is configured with is also accessible using HTTPS. In this way,
clients can upgrade to a more secure connection to the proxy.

## Background {#background}

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
that are identified by a URI or URI template. The fetch MUST use the "https" scheme
and the default port for HTTP over TLS, 443.

For example, a client would issue the following request for the PvD associated
with "https://proxy.example.org/masque{?target_host,target_port}":

~~~
:method = GET
:scheme = https
:authority = proxy.example.org
:path = /.well-known/pvd
accept = application/pvd+json
~~~

A client would send the same request as above for the PvD
assocated with an HTTP CONNECT proxy on "proxy.example.org:8080".
Note that the client will not make a request to port 8080, but
to port 443.

Note that all proxies that are co-located on the same host share the same PvD
Additional Information. Proxy deployments that need separate PvD configuration properties
SHOULD use different hosts.

PvD Additional Information is required to contain the "identifier", "expires", and
"prefixes" keys. For proxy PvDs as defined in this document, the "identifier" MUST
match the hostname of the HTTP proxy. The "prefixes" array SHOULD be empty by default.

## Discovery via HTTPS/SVCB Records {#svcparamkey}

To allow clients to determine whether PvD Additional Information is available for a given proxy,
this document defines a new SvcParamKey in HTTPS and SVCB DNS records defined in {{!SVCB-DNS=RFC9460}}.

Presence of this SvcParamKey, named `pvd` indicates that the proxy host supports PvD discovery via
the well-known PvD URI ".well-known/pvd" defined in {{Section 4.1 of PVDDATA}}. The presence of this
key in an HTTPS or SVCB record signals that the proxy's PvD Additional Information can be fetched
using the "https" scheme from the proxy host on port 443 using the well-known path. The presentation and
wire-format values for `pvd` SvcParamKey MUST be empty.

A client receiving a DNS record like the following:

~~~
proxy.example.org. 3600 IN HTTPS 1 . alpn="h3,h2" pvd
~~~

can interpret the presence of the pvd key as an indication that it MAY perform a PvD fetch from
"https://proxy.example.org/.well-known/pvd" using HTTP GET method.

While this key is particularly useful for detecting proxy configurations when
looking up a DNS record for a known proxy name, this key generically provides
a hint that PvD Additional Information is available, and can be used for use
cases unrelated to proxies.
This marker is advisory; clients MAY still attempt to fetch PvD Additional Information even if
`pvd` SvcParamKey is not present.

The `pvd` SvcParamKey is registered with IANA as described in {{svcparamkey-iana}}.

# Enumerating proxies within a PvD {#proxy-enumeration}

This document defines a new PvD Additional Information key, `proxies`, that
is an array of dictionaries, where each dictionary in the array defines
a single proxy that is available as part of the PvD (see {{proxies-key-iana}}).
Each proxy is defined by a proxy protocol and a proxy location (i.e., a hostname and port or a URI template
{{!URITEMPLATE=RFC6570}}), along with other optional keys.

When a PvD that contains the `proxies` key is fetched from a known proxy
using the method described in {{proxy-pvd}}, the proxies list describes
equivalent proxies (potentially supporting other protocols) that can be used
in addition to the known proxy.

Such cases are useful for informing clients of related proxies as a discovery
method, with the assumption that the client already is aware of one proxy.
Many historical methods of configuring a proxy only allow configuring
a single FQDN hostname for the proxy. A client can attempt to fetch the
PvD information from the well-known URI to learn the list of complete
URIs that support non-default protocols, such as {{CONNECT-UDP}} and
{{CONNECT-IP}}.

## Proxy definition keys

This document defines two required keys for the sub-dictionaries in the
`proxies` array: `protocol` and `proxy`. There are also optional keys, including
`mandatory`, `alpn`, and `identifier`. Other optional keys can be added to the
dictionary to further define or restrict the use of a proxy. The keys
are registered with IANA as described in {{proxy-info-iana}}, with the initial
content provided below.

| JSON Key | Optional | Description | Type | Example |
| --- | --- | --- | --- | --- |
| protocol | No | The protocol used to communicate with the proxy | String | "connect-udp" |
| proxy | No | String containing the URI template or hostname and port of the proxy, depending on the format defined by the protocol | String | "https://proxy.example.org:4443/masque{?target_host,target_port}" |
| mandatory | Yes | An array of optional keys that client must understand and process to use this proxy | Array of Strings | ["example_key"] |
| alpn | Yes | An array of Application-Layer Protocol Negotiation protocol identifiers | Array of Strings | ["h3","h2"] |
| identifier | Yes | A string used to refer to the proxy, which can be referenced by other dictionaries, such as entries in `proxy-match`  | String | "udp-proxy" |
{: #proxy-information-keys-table title="Initial Proxy Information PvD Keys Registry Contents"}

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
{: #proxy-protocol-value-table title="Initial PvD Proxy Protocol Registry Contents"}

The value of `proxy` depends on the Proxy Location Format defined by proxy protocol.
The types defined here either use a hostname and port, or a full URI template.

The value of the `mandatory` key is a list of keys that the client must understand and process to be
able to use the proxy. A client that does not understand a key from the list or cannot fully process
the value of a key from the list MUST ignore the entire proxy definition.

The `mandatory` list can contain keys that are either:

- registered in an IANA registry, defined in {{proxy-info-iana}} and marked as optional;
- or proprietary, as defined in {{proxy-proprietary-keys}}

The `mandatory` list MUST NOT include any entries that are not present in the sub-dictionary.

If the `alpn` key is present, it provides a hint for the Application-Layer Protocol Negotiation
(ALPN) {{!ALPN=RFC7301}} protocol identifiers associated with this server. For HTTP proxies,
this can indicate if the proxy supports HTTP/3, HTTP/2, etc.

The value of `identifier` key is a string that can be used to refer to a particular
proxy from other dictionaries, specifically those defined in {{destinations}}. The
string value is an arbitrary JSON string. Identifier values MAY be duplicated
across different proxy dictionaries in the `proxies` array, which indicates
that all references from other dictionaries to a particular identifier value apply
to all matching proxies. Proxies without the `identifier` key are expected to accept any
traffic since their destinations cannot be contained in `proxy-match` array defined
in {{destinations}}.

## Proprietary keys in proxy configurations {#proxy-proprietary-keys}

Implementations MAY include proprietary or vendor-specific keys in the sub-dictionaries of the `proxies`
array to convey additional proxy configuration information not defined in this specification.

A proprietary key MUST contain at least one underscore character ("_"). This character serves as a
separator between a vendor-specific namespace and the key name. For example, "acme_authmode" could
be a proprietary key indicating an authentication mode defined by a vendor named "acme".

When combined with `mandatory` list, this mechanism allows implementations to extend proxy metadata while
maintaining interoperability and ensuring safe fallback behavior for clients that do not support a given
extension.

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
content-length = 322

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

From this response, the client would learn the URI template of the proxy that supports UDP using {{CONNECT-UDP}},
at "https://proxy.example.org/masque{?target_host,target_port}".

# Destination accessibility information for proxies {#destinations}

Destination accessibility information is used when only a subset of destinations is reachable through
a proxy. Destination restrictions are often used in VPN tunnel configurations such as split
DNS in IKEv2 {{?IKEV2SPLIT=RFC8598}}, and in other proxy configuration mechanisms like PAC files (see {{background}}).

PvD Additional Information can be used to indicate that a set of proxies only allows access to
a limited set of destinations.

To support determining which traffic is supported by different proxies, this document defines
a new PvD Additional Information key `proxy-match`. This key has a value that is an array of
dictionaries, where each subdictionary describes a rule for matching traffic to one or more
proxies, or excluding the traffic from all proxies described in the PvD. These subdictionaries are referred
to as "destination rules", since they define rules about which destinations can be accessed
for a particular proxy or set of proxies.

## Destination Rule Keys

This document defines four keys for destination rules. Any destination rule MUST contain
the `proxies` key. Values corresponding to the `proxies` key may be either an empty array,
which implies that no proxy defined in this PvD can process matching traffic, or an array of strings
with at least one proxy `identifier` string. All destination rules MUST also contain at least one
other key use to describe the destination properties. Each key MUST correspond to an array
with at least one entry.

Extensions or proprietary deployments can define new keys to describe destination properties.
Any destination rules that include keys not known to the client, or values that cannot be
parsed, MUST be ignored in their entirety.

Destination rule keys are registered with IANA as defined in {{proxy-destination-iana}},
with the initial content provided below.

| JSON Key | Optional | Description | Type | Example |
| --- | --- | --- | --- | --- |
| proxies | No | An array of strings that match `identifier` values from the top-level `proxies` array | Array of Strings | ["tcp-proxy", "udp-proxy"] |
| domains | Yes | An array of FQDNs and wildcard DNS domains | Array of Strings | ["www.example.com", "\*.internal.example.com"] |
| subnets | Yes | An array of IPv4 and IPv6 addresses and subnets | Array of Strings | ["2001:DB8::1", "192.0.2.0/24"] |
| ports | Yes | An array of TCP and UDP port ranges | Array of Strings | ["80", "443", "1024-65535"] |
{: #destination-rule-keys-table title="Initial PvD Proxy Destination Rule Registry Contents"}

The `domains` array includes specific FQDNs and zones that are either accessible using specific proxy (for
rules with non-empty `proxies` array) or non-accessible through any proxies (for rules with empty `proxies` array).
A wildcard prefix (`*.`) is used to indicate matching entire domains or subdomains instead of
specific hostnames. Note that this can be used to match multiple levels of subdomains. For example "\*.example.com"
matches "internal.example.com" as well as "www.public.example.com".
Entries that include the wildcard prefix also MUST be treated as if they match
an FQDN that only contains the string after the prefix, with no subdomain. So,
an entry "\*.example.com" in the `domains` array of a `proxy-match` rule would match the FQDN "example.com".
This is done to prevent commonly needing to include both "\*.example.com" and "example.com"
in the `domains` array of a `proxy-match` rule.

The `subnets` array includes IPv4 and IPv6 address literals, as well as IPv4 and IPv6 address subnets
written using CIDR notation. Subnet-based destination information is only meant be used when applications
are communicating with destinations identified by only an IP address, and not a hostname.

Destination rules SHOULD NOT contain both the `domains` key and the `subnets` key. Many
clients will not resolve a domain being accessed through the proxy to an IP address before using
a proxy, so the subnet information may not be available.

The `ports` array includes specific ports (used for matching TCP and/or UDP ports), as well as
ranges of ports written with a low port value and a high port value, with a `-` in between.
For example, "1024-2048" matches all ports from 1024 to 2048, including the 1024 and 2048.
If `ports` key is not present, all ports are assumed to match. Comma-separated port list may
contain individual port numbers (such as "80") or inclusive ranges of ports. For example
"1024-2048" matches all ports from 1024 to 2048, including the 1024 and 2048.

##  Using Destination Rules

The destination rules can be used to determine which traffic can be sent through proxies, and
which specific set of proxies to use for any particular connection. By evaluating the rules in
order, a consistent behavior for usage can be achieved.

Rules in the `proxy-match` list SHOULD be provided in order of priority, such that a client
can evaluate the list of rules from the first in the array to the last in the array, and attempt
using the matching proxy or proxies from the earliest matching rule first. If earliest matching
rule has empty list of `proxies` client SHOULD NOT send matching traffic to any proxy defined
in this PvD. Multiple rules can match for the same destination, in which case all are considered
to be accessible through the matching proxies in case the sets of proxies are different.

In order to match a destination rule in the `proxy-match` list, all properties MUST apply. For
example, if a destination rule includes a `domains` array and a `ports` array, traffic that matches
the rule needs to match at one of the entries in the `domains` array and one of the entries in the
`ports` array.

A matched rule will then either point to one or more proxy `identifier` values, which correspond
to proxies defined in the list from {{proxy-enumeration}}, or instructs the client to not send the
matching traffic to any proxy. If a matching rule contains more then one `identifier` the client
should treat the list as an ordered list, where the first `identifier` is the most preferred.
Multiple proxy dictionaries can contain the same `identifier` value. In this case, the client
can choose any of the proxies; however, the client ought to prefer using the same proxy for the consecutive requests
to the same proxy `identifier` to increase connection reuse.

Entries listed in a `proxy-match` object MUST NOT expand the set of destinations that a client is
willing to send to a particular proxy. The list can only narrow the list of destinations
that the client is willing to send through the proxy. For example, if the client
has a local policy to only send requests for "\*.example.com" to a proxy
"proxy.example.com", and `domains` array of a `match` object contains "internal.example.com" and
"other.company.com", the client would end up only proxying "internal.example.com"
through the proxy.

## Proprietary Keys in Destination Rules

Implementations MAY include proprietary or vendor-specific keys in destination rules to define custom matching logic
not specified in this document.

Similar to proprietary keys in proxy definitions ({{proxy-proprietary-keys}}), a proprietary key in destination
rule MUST contain at least one underscore character ("\_"), which separates a vendor-specific namespace from the key name.
For example, "acme_processid" could be a key used to apply rules only to traffic of a specific process identifier as
defined by a vendor named "acme".

Clients that encounter a proprietary key they do not recognize MUST ignore the entire destination rule in which the
key appears. This ensures that unknown or unsupported matching logic does not inadvertently influence proxy selection
or bypass security controls. This handling applies uniformly across all match rules, including fallback rules.

## Examples

In the following example, two proxies are defined with a common identifier ("default_proxy"), with
a single destination rule for "\*.internal.example.org".

~~~
{
  "identifier": "proxy.example.org.",
  "expires": "2023-06-23T06:00:00Z",
  "prefixes": [],
  "proxies": [
    {
      "protocol": "http-connect",
      "proxy": "proxy.example.org:80",
      "identifier": "default_proxy"
    },
    {
      "protocol": "http-connect",
      "proxy": "proxy2.example.org:80",
      "identifier": "default_proxy"
    }
  ],
  "proxy-match": [
    {
      "domains": [ "*.internal.example.org" ],
      "proxies": [ "default_proxy" ]
    }
  ]
}
~~~

The client could then choose to use either proxy associated with the "default_proxy" identifier
for accessing TCP hosts that fall within the "\*.internal.example.org" zone. This would include the
hostnames "internal.example.org", "foo.internal.example.org", "www.bar.internal.example.org" and
all other hosts within "internal.example.org". The client will use the same proxy for the following
requests to hosts falling into the "\*.internal.example.org" zone to increase connection reuse and make
use of the connection resumption.

In the next example, two proxies are defined with a separate identifiers, and there are
three destination rules:

~~~
{
  "identifier": "proxy.example.org.",
  "expires": "2023-06-23T06:00:00Z",
  "prefixes": [],
  "proxies": [
    {
      "protocol": "http-connect",
      "proxy": "proxy.example.org:80",
      "identifier": "default_proxy"
    },
    {
      "protocol": "http-connect",
      "proxy": "special-proxy.example.org:80",
      "identifier": "special_proxy"
    }
  ],
  "proxy-match": [
    {
      "domains": [ "*.special.example.org" ],
      "ports": [ "80", "443", "49152-65535" ],
      "proxies": [ "special_proxy" ]
    },
    {
      "domains": [ "no-proxy.internal.example.org" ],
      "proxies": [ ]
    },
    {
      "domains": [ "*.internal.example.org" ],
      "proxies": [ "default_proxy" ]
    }
  ]
}
~~~

In this case, the client would use "special-proxy.example.org:80"
for any TCP traffic that matches "\*.special.example.org" destined to ports 80, 443 or any port between
49152 and 65535. The client would not use any of the defined proxies for access to
"no-proxy.internal.example.org". And finally, the client would use
"proxy.example.org:80" to access any other TCP traffic that matches
"\*.internal.example.org".

In the following example, three proxies are sharing a common identifier ("default-proxy"), but use
separate protocols constraining the traffic that they can process.

~~~
{
  "identifier": "proxy.example.org.",
  "expires": "2023-06-23T06:00:00Z",
  "prefixes": [],
  "proxies": [
    {
      "protocol": "http-connect",
      "proxy": "proxy.example.org:80",
      "identifier": "default_proxy"
    },
    {
      "protocol": "connect-udp",
      "proxy": "https://proxy.example.org/masque/udp/{target_host},{target_port}",
      "identifier": "default_proxy"
    },
    {
      "protocol": "connect-ip",
      "proxy": "https://proxy.example.org/masque/ip{?target,ipproto}",
      "identifier": "default_proxy"
    }
  ],
  "proxy-match": [
    {
      "domains": [ "*.internal.example.org" ],
      "proxies": [ "default_proxy" ]
    }
  ]
}
~~~

The client would use proxies in the following way:

- Traffic not destined to hosts within the "\*.internal.example.org" zone is not sent
to any proxy defined in this configuration
- TCP traffic destined to hosts within the "\*.internal.example.org" zone is sent
either to the proxy with "http-connect" protocol or to the proxy with "connect-ip" protocol
- UDP traffic destined to hosts within the "\*.internal.example.org" zone is sent
either to the proxy with "connect-udp" protocol or to the proxy with "connect-ip" protocol
- Traffic other than TCP and UDP destined to hosts within the "\*.internal.example.org" zone is sent
to the proxy with "connect-ip" protocol

The following example provides a configuration of proxies to be used by default with a
set with exceptions to bypass:

~~~
{
  "identifier": "proxy.example.org.",
  "expires": "2023-06-23T06:00:00Z",
  "prefixes": [],
  "proxies": [
    {
      "protocol": "http-connect",
      "proxy": "proxy.example.org:80",
      "identifier": "default_proxy"
    },
    {
      "protocol": "http-connect",
      "proxy": "backup.example.org:80",
      "identifier": "secondary_proxy"
    }
  ],
  "proxy-match": [
    {
      "domains": [ "*.intranet.example.org" ],
      "proxies": [ ]
    },
    {
      "subnets": [ "192.168.0.0/16", "2001:DB8::/32" ],
      "proxies": [ ]
    },
    {
      "proxies": [ "default_proxy", "secondary_proxy" ]
    }
  ]
}
~~~

In this case, the client would not send to the proxies any TCP traffic
that is not destined to hosts matching "\*.intranet.example.org", 192.168.0.0/16 or 2001:DB8::/32.
Due to the order in "proxies" list in the last rule of "proxy-match", the client would prefer
"proxy.example.org:80" over "backup.example.org:80"

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

The mechanisms in this document allow clients using a proxy to "upgrade" a configuration
for a cleartext HTTP/1.1 or SOCKS proxy into a configuration that uses TLS to communication to the proxy.
This upgrade can add protection to the proxied traffic so it is less observable by
entities along the network path; however it does not prevent the proxy itself from
observing the traffic being proxied.

Configuration advertised via PvD Additional Information, such DNS zones or associated
proxies, can only be safely used when fetched over a secure TLS-protected connection,
and the client has validated that that the hostname of the proxy, the identifier of
the PvD, and the validated hostname identity on the certificate all match.

When using information in destination rules ({{destinations}}), clients MUST only allow
the PvD configuration to narrow the scope of traffic that they will send through a proxy.
Clients that are configured by policy to only send a particular set of traffic through
a particular proxy can learn about rules that will cause them to send more narrowly-scoped
traffic, but MUST NOT send traffic that would go beyond what is allowed by local policy.

# IANA Considerations

## New PvD Additional Information key {#proxies-key-iana}

This document registers two new keys in the "Additional Information PvD Keys" registry.

### `proxies` Key

JSON Key: proxies

Description: Array of proxy dictionaries associated with this PvD

Type: Array of dictionaries

Example:

~~~
[
 {
  "protocol": "connect-udp",
  "proxy": "https://proxy.example.org/masque{?target_host,target_port}"
 }
]
~~~

### `proxy-match` Key

JSON Key: proxy-match

Description: Array of proxy match rules, as dictionaries, associated with
entries in the `proxies` list.

Type: Array of dictionaries

Example:

~~~
[
 {
  "domains": [ "*.internal.example.org" ],
  "proxies": [ "default_proxy" ]
 }
]
~~~

## New PvD Proxy Information Registry {#proxy-info-iana}

IANA is requested to create a new registry "Proxy Information PvD Keys", within the "Provisioning Domains (PvDs)" registry page.
This new registry reserves JSON keys for use in sub-dictionaries under the `proxies` key.
The initial contents of this registry are given in {{proxy-information-keys-table}}.

New assignments in the "Proxy Information PvD Keys" registry will be administered by IANA through Expert Review {{!RFC8126}}. Experts are
requested to ensure that defined keys do not overlap in names or semantics.

## New PvD Proxy Protocol Registry {#proxy-protocol-iana}

IANA is requested to create a new registry "Proxy Protocol PvD Values", within the "Provisioning Domains (PvDs)" registry page.
This new registry reserves JSON values for the `protocol` key in `proxies` sub-dictionaries.
The initial contents of this registry are given in {{proxy-protocol-value-table}}.

New assignments in the "Proxy Protocol PvD Values" registry will be administered by IANA through Expert Review {{RFC8126}}.
Experts are requested to ensure that defined keys do not overlap in names or semantics, do not contain an underscore character ("\_")
in the names (since underscores are reserved for vendor-specific keys), and have clear format definitions.
The reference and notes fields MAY be empty.

## New PvD Proxy Destination Rule Registry {#proxy-destination-iana}

IANA is requested to create a new registry "Proxy Destination Rule PvD Keys", within the "Provisioning Domains (PvDs)" registry page.
This new registry reserves JSON keys for use in sub-dictionaries under the `proxy-match` key.
The initial contents of this registry are given in {{destination-rule-keys-table}}.

New assignments in the "Proxy Destination Rule PvD Keys" registry will be administered by IANA through Expert Review {{RFC8126}}.
Experts are requested to ensure that defined keys do not overlap in names or semantics, and do not contain an underscore character ("\_")
in the names (since underscores are reserved for vendor-specific keys).

## New DNS SVCB Service Parameter Key (SvcParamKey) {#svcparamkey-iana}

IANA is requested to add a new entry to the "DNS SVCB Service Parameter Keys (SvcParamKeys)" registry:

* Number: TBD
* Name: pvd
* Meaning: PvD configuration is available at the well-known path
* Change Controller: IETF
* Reference: this document, {{svcparamkey}}
