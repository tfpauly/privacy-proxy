---
title: The Privacy Token HTTP Authentication Scheme
abbrev: HTTP Privacy Token
docname: draft-privacy-token-latest
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


normative:
    RSASIG:
      target: https://chris-wood.github.io/draft-wood-cfrg-blind-signatures/draft-wood-cfrg-rsa-blind-signatures.html
      title: RSA Blind Signatures
      date: 2020

--- abstract

This documents defines an authentication scheme for HTTP called Privacy Token.

--- middle

# Introduction {#introduction}

This document defines a new HTTP authentication scheme {{!RFC7235}}
named "PrivacyToken".

This scheme is built to be used to authenticate to proxies, using the
Proxy-Authorization header field, with a blind signature that allows a proxy
to verify that a client has a token signed by a particular key, but without
identifying the client. The initial version of this scheme is intended to be
used with RSA Blind Signatures {{RSASIG}}.

## Requirements

{::boilerplate bcp14}

# PrivacyToken Authentication Scheme {#scheme}

The "PrivacyToken" authentication scheme defines four parameters: "v", "k", "m", and "s".
All unknown or unsupported parameters to "PrivacyToken" authentication
credentials MUST be ignored.

As an example, a Proxy-Authorization field in an HTTP request would look like:

~~~
Proxy-Authorization: PrivacyToken v=1 k=dzAwdA m=123... s=abc...
~~~

## Version Parameter ("v")

The value of the "v" parameter is an integer version identifier that identifies the
signature algorithm being used.

This document defines a single version, 1, that indicates use of
private tokens based on RSA Blind Signatures.

## Key ID Parameter ("k")

The value of the "k" parameter is a truncated key ID that identifies
the key used to produce the signature. This is a four-byte value, encoded
using base64url encoding {{!RFC4648}}.

## Message Parameter ("m")

The value of the "m" parameter is a random message that is signed by the
signature in "s", encoded using base64url encoding {{!RFC4648}}.

## Signature Parameter ("s")

The value of the "s" parameter is a signature that covers the message,
encoded using base64url encoding {{!RFC4648}}.

For version 1, this signature is a RSA Blind Signature.

# IANA Considerations {#iana}

This document registers the "PrivacyToken" authentication scheme in the
"Hypertext Transfer Protocol (HTTP) Authentication Scheme Registry"
established by {{!RFC7235}}.

Authentication Scheme Name:  PrivacyToken

Pointer to specification text:  {{scheme}} of this document
