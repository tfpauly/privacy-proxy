---
title: HTTP Proxy-Status Parameter for DNS Information
abbrev: Proxy-Status DNS Info
docname: draft-pauly-masque-dns-proxy-status-latest
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

This document defines an HTTP Proxy-Status Parameter that contains the IP address
and CNAME chain received over DNS that was used to establish the connection to the
next hop.

--- middle

# Introduction

The Proxy-Status HTTP response field {{!PROXY-STATUS=RFC9209}} allows proxies to convey
information about how a proxied request was handled in HTTP responses sent to clients.
It defines a set of parameters that provide information, such as the name of the next
hop.

The Proxy-Status field can be sent by both forward proxies and gateways (or "reverse
proxies"). In the case of forward proxies, clients are requesting to establish TCP
connections (using the CONNECT method {{!HTTP=RFC9110}}) and UDP connections
(using UDP proxying {{!CONNECT-UDP=RFC9298}}) to a target server. This target server
can be specified using either a hostname or an IP address. When using a name instead
of an IP address, the forward proxy locally performs DNS resolution to resolve the
name to an IPv4 or IPv6 address using A or AAAA queries.

Clients of forward proxies currently don't have visibility into the DNS resolution
that is performed on the proxy. If available, this information could be used by clients
to help make various decisions that are influenced by IP addresses and CNAME chains.
For example, some clients classify specific names and IP addresses as being used
for collecting data to track users (which can be used to influence policies for
HTTP cookies), or can recognize them as endpoints that ought to be blocked for
features like ad blocking or malware blocking. Without this information, proxying
using a forward proxy means that clients lose the ability to fully recognize servers
based on IP addresses and CNAME chains.

It is possible for clients to perform DNS resolution before using a forward proxy,
and proxy using IP addresses, but this has several drawbacks: performing
DNS without using the proxy can lead a privacy regression, or a performance regression
if the addresses selected are not optimal for connectivity from the proxy; proxying
by IP address prevents the proxy from selecting the best address
({{?HAPPY-EYEBALLS=RFC8305}}); and if clients try to resolve via the proxy
using DNS over HTTPS ({{?DOH=RFC8484}}), they can incur a performance hit by requiring
an extra round trip before being able to establish a connection.

This document allows clients to receive the IP address and CNAME chain received from
DNS, without needing to perform DNS on the client, by including the information in
a Proxy-Status parameter ({{dns-used}}).

## Requirements

{::boilerplate bcp14}

# dns-used Parameter {#dns-used}

The dns-used parameter's value is a String that contains one or more IP addresses and/or
DNS names in a comma-separated list. The first item in the list SHOULD be the IP address
that was resolved using DNS and was used to open connectivity to the next hop. The
remaining items in the list SHOULD include all names received in CNAME records {{!DNS=RFC1912}} or
AliasMode SVCB records {{!SVCB=I-D.ietf-dnsop-svcb-https}} during the course of resolving
the address.

For example:

~~~ example
Proxy-Status: proxy.example.net; next-hop=target.example.com dns-used="12.12.12.12,tracker.example.com."
~~~

indicates that proxy.example.net, which used target.example.com as the next hop for this request, used
the IP address "12.12.12.12" to connect to the target, and encountered the CNAME "tracker.example.com."
in DNS resolution chain. Note that while this example includes both the next-hop and dns-used
parameters, dns-used can be included without including next-hop.

The dns-used parameter only applies when DNS was used to resolve the next hop's name, and
does not apply in all situations. Clients can use the information in this parameter to determine
how to use the connection established through the proxy, but need to gracefully handle situations
in which this parameter is not present.

# Security Considerations {#sec-considerations}

The dns-used parameter does not include any DNSSEC information or imply that DNSSEC was used.
The information included in the parameter can only be trusted to be valid insofar as the client
trusts its proxy to provide accurate information. This information is intended to be used as
a hint, and SHOULD NOT be used for making security decisions about the identity resource access
through the proxy.

# IANA Considerations

This document registers the "dns-used" parameter
in the "HTTP Proxy-Status Parameters" registry
<[](https://www.iana.org/assignments/http-proxy-status)>.

Name:
: dns-used

Description:
: A string containing the IP address used to establish the proxied connection
and the chain of CNAMEs that led to this IP address.

Reference:
: This document
