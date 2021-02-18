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
 -  ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    email: caw@heapingbits.net


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

# Privacy Token Structure {#struct}

A privacy token is a structure that begins with a single byte that indicates
a version. This document defines version, 1, which indicates use of
private tokens based on RSA Blind Signatures, and determines the rest
of the structure contents.

~~~
struct {
    uint8_t version;
    uint8_t key_id[8];
    uint8_t message[32];
    uint8_t signature[Nk];
} Token;
~~~

The structure fields are defined as follows:

- "version" is a 1-octet integer. This document defines version 1.

- "key_id" is a 8-octet truncated key ID that identifies the key used to produce
the signature. This is generated as SHA256(public_key)[0:32], where public_key
is a DER-encoded SubjectPublicKeyInfo object carrying the public key.

- "message" is a 32-octet random message that is signed by the
signature.

- "signature" is a Nk-octet RSA Blind Signature that covers the message.
For version 1, Nk is 512.

# PrivacyToken Authentication Scheme {#scheme}

The "PrivacyToken" authentication scheme defines one parameter, "token".
All unknown or unsupported parameters to "PrivacyToken" authentication
credentials MUST be ignored.

The value of the "token" parameter is a Privacy Token Structure {{struct}},
encoded using base64url encoding {{!RFC4648}}.

As an example, a Proxy-Authorization field in an HTTP request would look like:

~~~
Proxy-Authorization: PrivacyToken token=abc...
~~~

# Security Considerations {#security}

Note that the KeyID is only a hint to identify the public verification key. With
a sufficiently large number of public keys, KeyID collisions may occur.
By approximation, a KeyID collision between two distinct keys will occur
with probability sqrt(p * 2^33). In such cases, servers SHOULD attempt
verification using both keys.

# IANA Considerations {#iana}

This document registers the "PrivacyToken" authentication scheme in the
"Hypertext Transfer Protocol (HTTP) Authentication Scheme Registry"
established by {{!RFC7235}}.

Authentication Scheme Name:  PrivacyToken

Pointer to specification text:  {{scheme}} of this document
