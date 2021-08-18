---
title: Private Access Tokens
abbrev: Private Access Tokens
docname: draft-private-access-tokens-latest
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

--- abstract

This document defines a protocol for issuing and redeeming privacy-preserving
access tokens. These tokens can adhere to an issuance policy, allowing a
service to limit access according to the policy without tracking client identity.

--- middle

# Introduction {#introduction}

In many systems, passive, persistent signals such as IP addresses are used for
enforcing policies. Typically, servers use these signals as weak client identifiers.
Clients coming from a single IP address may be limited in how much content
they can access over a given time period (often referred to as a "metered paywall"),
or access from an IP address may be rate-limited to prevent fraud and abuse.
When the IP address signal is unavailable, perhaps due to the use of a proxy network,
servers are left without a suitable functional replacement.

This document proposes using Private Acess Tokens, using RSA Blind Signatures as defined
in {{!PRIVATETOKEN=I-D.privacy-token}}, as a replacement for these signals. These tokens
are privately issued to clients and then redeemed by servers in such a way that the
issuance and redemption events for a given token are unlinkable. Fundamentally, using
tokens in lieu of per-client signals for policy enforcement seemingly requires some entity
to know both the client and policy. However, with appropriate mediation and
sesparation between parties involved in the issuance and redemption protocols,
it is possible to limit this information leakage without functional regressions.

This document describes a protocol for mediating the issuance and redemption
of Private Access Tokens with the following properties:

1. The Mediator enforces and maintains a mapping between client identifiers
   and anonymous identifiers;
1. The Issuer enforces policies keyed by anonymous client identifier and origin
   identifier, without learning the real client identity; and
1. The Redeemer learns whether a given client has a valid Private Access Token for
   its origin policy.

## Requirements

{::boilerplate bcp14}

# Overview

The protocol involves four entites:

1. Client: the entity responsible for requesting Private Access Tokens and redeeming them.
1. Mediator: the entity responsible for authenticating Clients, using information such as
   account names or device identities.
1. Issuer: the entity responsible for issuing Private Access Tokens on behalf of a given Redeemer,
   according to the Redeemer's policy.
1. Redeemer: the entity responsible for verifying Private Access Tokens and providing a service
   to the Client.

In this architecture, the Mediator, Issuer, and Redeemer each have limited knowledge
regarding the Client's actions, and only know enough to provide their necessary
functionality. The pieces of information are identified in {{terms}}.

The Mediator is able to see the Client's actual identity information (CLIENT_ID), the Issuer
being targeted (ISSUER_NAME), and the period of time for which the Issuer's policy is valid
(ISSUER_POLICY_WINDOW). The Mediator does not know the identity of the service the Client
is trying to access (ORIGIN_ID), but instead sees an anonymous version (ANON_ORIGIN_ID).

The Issuer is able to see the identity of the service (ORIGIN_ID), but only sees an
anonymous identifier for a client (ANON_CLIENT_ID). Issues maintain the details of
policy enforcement on behalf of the Redeemer. For example, a given policy might be,
"issue at most N tokens to each client." Example policies and their use cases are
discussed in {{policies}}.

The Redeemer, which represents the service being accessed by the client, only receives
a Private Access Token from the client.

## Terminology {#terms}

The following terms are defined to refer to the different pieces of information
passed through the system:

ISSUER_NAME:
: The Issuer Name identifies which Issuer is able to provide tokens for a Client.
The Client sends the Issuer Name to the Mediator so the Mediator know where to
forward requests. Each Issuer is associated with a specific ISSUER_POLICY_WINDOW.

ISSUER_POLICY_WINDOW:
: The Issuer Policy Window defines the period over which an Issuer will track access
policy. The ANON_CLIENT_ID that the Mediator derives is specific to a Policy Window,
meaning that a CLIENT_ID will not map to the same ANON_CLIENT_ID after the Policy
Window has elapsed.

ORIGIN_ID:
: The Origin Identifier represents the service for which the Client is requesting a
Private Access Token. Conceptually, this can map to a website. The Origin Identifier
corresponds to a single public key that can be used to sign tokens.

ANON_ORIGIN_ID:
: The Anonymous Origin Identifier is generated by the Client and marked on requests
to the Mediator and through to the Issuer.

CLIENT_ID:
: The Client Identifier represents a single client that has authenticated to the Mediator.
The specifics of this identity are up to the Mediator, but it may be based on an
attested device identifier or an account login that the Mediator can verify.

ANON_CLIENT_ID:
: The Anonymous Client Identifier is generated by the Mediator and used when forwarding
requests to the Issuer. The Mediator maintains a mapping such that there is exactly one
ANON_CLIENT_ID for each CLIENT_ID + ANON_ORIGIN_ID pair during a specific ISSUER_POLICY_WINDOW.

# API Endpoints

It is assumed that issuers make Oblivious HTTP configurations and policy verification
keys available via the following API endpoints:

- OHTTP configuration: /.well-known/ohttp-config
- Policy verification key: /.well-known/verification-key/policy=?

[OPEN ISSUE: Provide an API to let the Mediator learn the ISSUER_POLICY_WINDOW]

The OHTTP configuration is defined in {{!OHTTP=I-D.thomson-http-oblivious-http}}.
The public verification key is a struct of the following format:

~~~
struct {
  opaque public_key[Nk]; // Defined in I-D.irtf-cfrg-rsa-blind-signatures
} VerificationKey;
~~~

The contents of VerificationKey are an RSA public key for use with the RSA Blind
Signature protocol {{!BLINDSIG=I-D.irtf-cfrg-rsa-blind-signatures}}.

Mediators advertise an Oblivious HTTP URI template for proxying protocol messages
to issuers with a known URI Template {{!RFC6570}}. For example, one template
for the Mediator might be https://mediator.net/proxy-token-request{?request}.

# Issuance

Issuance assumes the Client has the following information:

- Origin token public key, a blind signature public key, denoted `pkO`
- ORIGIN_ID, a 32-byte collision-resistant hash that identifies the origin token public key

Moreover, it assumes that the Client and Mediator have a secure and
mutually authenticated connection. This is necessary for the Mediator to identify
the Client.

Before starting the issuance process, the Client generates the ANON_ORIGIN_ID,
a random collision-resistant 32-byte value. The Client stores a mapping between the
ORIGIN_ID and the generated ANON_ORIGIN_ID for future requests.

Issuance begins by Clients generating a Private Access Token request, starting as follows:

~~~
nonce = random(32)
blinded_req, blind_inv = rsabssa_blind(pkO, nonce)
~~~

[OPEN ISSUE: where do we talk about where the Client sends the actual ORIGIN_ID to the Issuer?]

[OPEN ISSUE: rewrite this in terms of a generic blind signature scheme (not RSA specific)]

The Client then constructs a policy-based Private Access Token request of the following
structure, encoded using TLS notation from {{!TLS13=RFC8446}}, Section 3:

~~~
struct {
  uint8_t anon_origin_id[32];
  opaque blinded_req[Nk];
} PrivateAccessTokenRequest;
~~~

The Client then generates an HTTP POST request to the Issuer with this request
as the body. The media type for this request is "application/policy-token-request".
Then the Client encapsulates this request using Oblivious HTTP and sends the response
to the Mediator's proxy URI.

Upon receipt, the Mediator computes the ANON_CLIENT_ID, which is a fixed-length byte string, for
the given Client. The mechanism for doing this is out of scope of the document. However,
the ANON_CLIENT_ID MUST be generated in such a way that any Client identifying information cannot
be recovered. It also MUST be unique for each ANON_ORIGIN_ID during a given ISSUER_POLICY_WINDOW.

[OPEN ISSUE: Does the mediator modify ANON_ORIGIN_ID into ANON_ORIGIN_ID_PRIME before passing to the issuer? Or does the client learn about the window changes and switch the ANON_ORIGIN_ID accordingly?]

Before forwarding the Client's encapsulated request to the Issuer, the Mediator includes a header
listing the ANON_CLIENT_ID, "Sec-CH-AnonymousClientID".

Upon receipt of the Client's encapsulated request, the Issuer checks for the "Sec-CH-AnonymousClientID"
header. If absent, the Issuer aborts and returns a 400 error to the Mediator. If present,
the Issuer decapsulates the request. If this fails, the Issuer aborts and returns a 400 error
to the Mediator.

[OPEN ISSUE: ensure this is compatible with OHTTP semantics]

If decapsulation succeeds, the Issuer uses the ANON_CLIENT_ID and PrivateAccessTokenRequest
to determine if a token can be generated. If the policy does not admit issuance, the Issuer aborts and returns
a 400 error to the Mediator. Otherwise, the Issuer completes the issuance flow by computing
a blinded response as follows:

~~~
blind_sig = rsabssa_blind_sign(skP, PrivateAccessTokenRequest.blinded_req)
~~~

The Issuer generates an HTTP response with status code 200 whose body consists of
blind_sig. The Issuer encapsulates this as the response to the Client's request
and sends the result to the Mediator. The Issuer then updates any local state
for the (ANON_CLIENT_ID, policy) tuple as needed. For example, if the policy is meant to
bound the number of tokens given to a given ANON_CLIENT_ID, then the Issuer should increment
the number of tokens issued for the given ANON_CLIENT_ID.

The Mediator forwards the encapsulated response to the Client without modification.

Upon receipt, the Client decapsulates the response and, if successful, processes the
body as follows:

~~~
sig = rsabssa_finalize(pkP, nonce, blind_sig, blind_inv)
~~~

If this succeeds, the Client then constructs a Private Access Token as described in
{{PRIVATETOKEN}} using the token nonce and output sig.

# Redemption

The Client is assumed to have the policy verification key before redeeming
a Private Access Token.

[OPEN ISSUE: describe how Clients can use OHTTP to fetch the policy key from Issuers]

Redeemers can request that tokens be spent by Clients for given resources
using the WWW-Authenticate header, as follows:

~~~
WWW-Authenticate: PrivacyToken realm="<policy>"
~~~

Upon receipt, Clients can spend a Private Access Token with the Authorize header, as follows:

~~~
Authorization: PrivacyToken t=abc
~~~

Where the token is a serialized Private Access Token corresponding to the given Redeemer
policy.

# Policies and Uses Cases {#policies}

TODO: example policies and deployments of this (diagram)

# Security Considerations {#security}

TODO

# IANA Considerations {#iana}

TODO: "application/policy-token-request" MIME type
TODO: "application/policy-key-request" MIME type

--- back
