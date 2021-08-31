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
   and anonymous redeemer identifiers;
1. The Issuer enforces policies keyed by anonymous client identifier and redeemer
   identifier, without learning the real client identity; and
1. The Redeemer learns whether a given client has a valid Private Access Token for
   its policy.

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
(ISSUER_POLICY_WINDOW). The Mediator does not know the identity of the Redeemer the Client
is trying to access (ORIGIN_ID), but instead sees an anonymous version (ANON_ORIGIN_ID).

The Issuer is able to see the identity of the Redeemer (ORIGIN_ID), but only sees an
anonymous identifier for a client (ANON_CLIENT_ID). Issuers maintain the details of
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
policy, defined in terms of seconds and represented as a uint64. The ANON_CLIENT_ID
that the Mediator derives is specific to a Policy Window, meaning that a CLIENT_ID
will not map to the same ANON_CLIENT_ID after the Policy Window has elapsed.

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

ANON_ORIGIN_ID_PRIME:
: The Anonymous Origin Identifier Prime is generated by the Mediator and sent to the Issuer,
and corresponds to a unique ANON_ORIGIN_ID and a unique ANON_CLIENT_ID.

# API Endpoints {#setup}

It is assumed that Issuers make Oblivious HTTP configurations and policy verification
keys available via the following API endpoints:

- OHTTP configuration: /.well-known/ohttp-config
- Access token policy verification key: /.well-known/access-token-key/policy=?
- Access token policy window: /.well-known/access-token-window/policy=?

The OHTTP configuration is defined in {{!OHTTP=I-D.thomson-http-oblivious-http}}.
The access token policy verification key is a struct of the following format:

~~~
struct {
  opaque public_key[Nk]; // Defined in [BLINDSIG]
} AccessTokenKey;
~~~

The contents of AccessTokenKey are an RSA public key for use with the RSA Blind
Signature protocol {{!BLINDSIG=I-D.irtf-cfrg-rsa-blind-signatures}}. The response
use media type "application/access-token-key".

The access token policy window is a resource of media type "application/json", with the
following structure:

~~~
{
   "access-token-window": <ISSUER_POLICY_WINDOW>
}
~~~

Issuers also advertise a Private Access Token request URI template {{!RFC6570}}
for generating access tokens. For example, one template for the Issuer might
be https://issuer.net/access-token-request.

Mediators advertise an Oblivious HTTP URI template {{!RFC6570}} for proxying
protocol messages to Issuers. For example, one template
for the Mediator might be https://mediator.net/relay-access-token-request.

# Issuance

Issuance assumes the Client has the following information:

- Origin name (ORIGIN_NAME), a URI referring to the Redeemer (origin) {{!RFC6454}};
- Origin token public key (ORIGIN_KEY), a blind signature public key; and
- Origin identifier (ORIGIN_ID), a 32-byte collision-resistant hash that identifies
  the origin token public key. See {{origin-id}} for details about its construction.

Issuance also assumes that Issuers maintain local state for each distinct (redeemer, policy)
tuple. In particular, for each tuple, Issuers maintain a stable mapping from ANON_CLIENT_ID
to ORIGIN_ID values, as well as a table from (ANON_CLIENT_ID, ORIGIN_ID) to policy state.
Policy state is intentionally opaque, though examples include simple counters to track
the number of tokens issued to a given (ANON_CLIENT_ID, ORIGIN_ID) pair.

Finally, Issuance assumes that the Client and Mediator have a secure and
Mediator-authenticated HTTPS connection. See {{sec-considerations}} for additional
about this channel.

Issuance begins by Clients generating a Private Access Token request, starting as follows:

~~~
nonce = random(32)
blinded_req, blind_inv = rsabssa_blind(ORIGIN_KEY, nonce)
~~~

The Client then constructs a Private Access Token request using blinded_req, encoded
using TLS notation from {{!TLS13=RFC8446}}, Section 3:

~~~
struct {
  opaque blinded_req[Nk];
} AccessTokenRequest;
~~~

The Client then generates an HTTP POST request to the Issuer with this request
as the body. The media type for this request is "message/access-token-request".
The Client includes the "Token-Origin" header in this request, whose value is
ORIGIN_NAME. An example request is shown below.

~~~
:method = POST
:scheme = https
:authority = issuer.net
:path = /access-token-request
accept = message/access-token-request
cache-control = no-cache, no-store
content-type = message/access-token-request
content-length = Nk
Token-Origin = https://example.com

<Bytes containing the AccessTokenRequest>
~~~

Then the Client encapsulates this request using Oblivious HTTP, yielding an encapsulated
HTTP message. The Client includes the "Anonymous-Origin-ID" header in this request,
whose value is ANON_ORIGIN_ID. Finally, the Client sends this encapsulated request to the
Mediator's proxy URI. An example request is shown below.

~~~
:method = POST
:scheme = https
:authority = mediator.net
:path = /relay-access-token-request
accept = message/ohttp-req
cache-control = no-cache, no-store
content-type = message/ohttp-req
content-length = ...
Anonymous-Origin-ID = ANON_ORIGIN_ID

<Bytes containing the encapsulated HTTP message for the Issuer>
~~~

Upon receipt, the Mediator computes ANON_CLIENT_ID, which is a fixed-length byte string
for the given Client. See {{client-id}} for details of its computation. The Mediator
also computes ANON_ORIGIN_ID_PRIME, a fixed-length byte string, for each ANON_ORIGIN_ID
for a specific ANON_CLIENT_ID. See {{origin-id}} for details its computation.

Before forwarding the Client's encapsulated request to the Issuer, the Mediator includes headers
listing both the ANON_CLIENT_ID, "Anonymous-Client-ID", and the ANON_ORIGIN_ID_PRIME,
"Anonymous-Origin-ID".

~~~
:method = POST
:scheme = https
:authority = issuer.net
:path = /access-token-request
accept = message/ohttp-req
cache-control = no-cache, no-store
content-type = message/ohttp-req
content-length = ...
"Anonymous-Origin-ID" = ANON_ORIGIN_ID_PRIME
"Anonymous-Client-ID" = ANON_CLIENT_ID

<Bytes containing the encapsulated HTTP message for the Issuer>
~~~

Note: although these headers are per-request, they do not reveal information about
the originating client. See {{client-id}} and {{origin-id}} for more details.

Upon receipt of the Client's encapsulated request, the Issuer checks for the "Anonymous-Client-ID"
and "Anonymous-Origin-ID" headers. If either is absent, the Issuer aborts and returns a 400 error
to the Mediator. If present, the Issuer decapsulates the request. If this fails, the Issuer aborts
and returns a 400 error to the Mediator. If decapsulation succeeds, the Issuer checks for the
"Target-Origin" header. If absent, the Issuer aborts and returns a 400 error to the Mediator.
If present, the Issuer proceeds extracts ANON_CLIENT_ID from the "Anonymous-Client-ID" header,
ANON_ORIGIN_ID from the "Anonymous-Origin-ID" header, and ORIGIN_NAME from the "Target-Origin"
header, and then proceeds as follows.

First, check to see if there are any prior token requests for the given (ANON_CLIENT_ID, ORIGIN_NAME) pair.
If so, and if the corresponding ANON_ORIGIN_ID does not match that of the current request, the
Issuer aborts and returns a 400 error to the Mediator.

If this is not the case, determine if the token request can be satisfied for the given
(ANON_CLIENT_ID, ORIGIN_NAME) pair, according to the access token policy. If the policy does not admit
issuance, the Issuer aborts and returns a 400 error to the Mediator.

If the Issuer local state and policy admit a token, the Issuer completes the issuance flow by
computing a blinded response as follows:

~~~
blind_sig = rsabssa_blind_sign(skP, AccessTokenRequest.blinded_req)
~~~

`skP` is the private key corresponding to ORIGIN_KEY, known only to the Issuer.

The Issuer generates an HTTP response with status code 200 whose body consists of
blind_sig. The Issuer encapsulates this as the response to the Client's request,
sets the media type to "message/access-token-response", and sends the result to
the Mediator.

The Issuer then updates any local state for the (ANON_CLIENT_ID, ORIGIN_KEY) tuple as
needed. For example, if the policy is meant to bound the number of tokens given to
a given ANON_CLIENT_ID, then the Issuer should increment the number of tokens issued
for the given ANON_CLIENT_ID.

The Mediator forwards the encapsulated response to the Client without modification.

Upon receipt, the Client decapsulates the response and, if successful, processes the
body as follows:

~~~
sig = rsabssa_finalize(ORIGIN_KEY, nonce, blind_sig, blind_inv)
~~~

If this succeeds, the Client then constructs a Private Access Token as described in
{{PRIVATETOKEN}} using the token nonce and output sig.

## Anonymous Client ID {#client-id}

ANON_CLIENT_ID MUST be generated in such a way that any Client identifying information cannot
be recovered. It also MUST be unique for each ANON_ORIGIN_ID during a given ISSUER_POLICY_WINDOW.
One possible derivation is to compute a pseudorandom function (PRF) keyed by CLIENT_ID over
ISSUER_POLICY_WINDOW, e.g., ANON_CLIENT_ID = HKDF(secret=CLIENT_ID, salt="", info=ISSUER_POLICY_WINDOW).

## Anonymous Origin ID {#origin-id}

ANON_ORIGIN_ID MUST be a stable and unpredictable 32-byte value computed by the Client.
Clients MUST NOT change this value across origins. Doing so will result in token issuance
failuer by the mediator.

One possible mechanism for implementing this identifier is for the Client to store a mapping
between the ORIGIN_NAME and a randomly generated ANON_ORIGIN_ID for future requests. Alternatively,
the Client can compute a PRF keyed by a per-client secret (CLIENT_SECRET) over the ORIGIN_NAME,
e.g., ANON_ORIGIN_ID = HKDF(secret=CLIENT_SECRET, salt="", info=ORIGIN_NAME).

Although clients generate ANON_ORIGIN_ID deterministically across ISSUER_POLICY_WINDOW periods,
mediators compute a different ANON_ORIGIN_ID_PRIME value for each new ISSUER_POLICY_WINDOW.
Issuers MUST NOT be able to recover ANON_ORIGIN_ID from ANON_ORIGIN_ID_PRIME. One possible
derivation is to compute a PRF keyed by ANON_ORIGIN_ID over ISSUER_POLICY_WINDOW, e.g.,
ANON_ORIGIN_ID_PRIME = HKDF(secret=ANON_ORIGIN_ID, salt="", info=ISSUER_POLICY_WINDOW).

# Redemption

The Client is assumed to have the policy verification key before redeeming
a Private Access Token.

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
policy. Redeemers verify the token using the corresponding policy verification key from the
Issuer. Redeemers are also expected to keep state of Private Access Tokens already spent;
see {{access-token-replay}} for discussion.

# Policies and Uses Cases {#policies}

This section describes various instantiations of this protocol to address common use cases.

## Client Re-Identification

In this example, a single site wishes to learn if a given user is unique. The site's only
requirement is to know if two otherwise distinct connections originate from the same
end-user, and nothing more. In particular, it is not important for the server to know if
two connections correspond to a specific user. The time window over which the server
needs to link such connections together can vary. Larger windows allow for larger
per-user linkability.

To instantiate this case, the site acts as a Redeemer and registers an "unlimited token"
policy with the Issuer. In this policy, the Issuer does not enforce any limit on the number
of tokens a given user will obtain.

Redeemers request tokens from clients and, upon successful redemption, the Redeemer knows
the client was able to request a token for the given (CLIENT_ID, ORIGIN_ID) tuple. As a
result, the Redeemer knows this is a unique client.

## Metered Paywalls

In this example, a site wishes to implement a metered paywall, wherein the meter is enforced
by a weak client identifier such as their IP address. The policy for such a paywall is to
limit the number of visits to unique users to some fixed value. The policy typically rotates
on a regular basis. For example, users may get N visits within the span of a week before the
paywall is enacted.

To instantiate this case, the site acts as a Redeemer and registers a "bounded token" policy
with the Issuer. In this policy, the Issuer does enforces a fixed number of tokens for a given
(ANON_CLIENT_ID, ORIGIN_ID) tuple.

Redeemers request tokens from clients and, upon successful redemption, the Redeemer knows
the client was able to request a token for the given (CLIENT_ID, ORIGIN_ID) tuple within
its budget. Failure to present a token can be interpreted as a signal that the client's token
budget was exceeded.

# Security Considerations {#sec-considerations}

This section discusses security considerations for the protocol.

[OPEN ISSUE: discuss trust model]

## Client Identity

The HTTPS connection between Client and Mediator is minimally Mediator-authenticated. Mediators
can also require Client authentication if they wish to restrict Private Access Token proxying
to trusted or otherwise authenticated Clients. Absent some form of Client authentication, Mediators
can use other per-Client information for the client identifier mapping, such as IP addressess.

## Denial of Service

Requesting and verifying a Private Access Token is more expensive than checking an implicit
signal, such as an IP address, especially since malicious clients can generate garbage
Private Access Tokens and for Redeemers to work. However, similar DoS vectors already exist
for Redeemers, e.g., at the underlying TLS layer.

## Access Token Replay

Redeemers are required to track when Private Access Tokens are spent. Failure to do so may
allow malicious clients to replay tokens more than once. However, given that existing solutions
to this problem already require Redeemers to carry per-client state, this additional cost is not
a new requirement.

[OPEN ISSUE: replay state is a tradeoff agaist mediator and issuer availability -- if the latter
services were highly available, then redeemers could include a fresh challenge to be folded into
the Private Access Token, removing the need for any redeemer state.]

## Access Token Verification Keys {#access-token-keys}

Issuer verification keys MUST be unique for each (redeemer, policy) pair. Sharing policies
or keys across redeemers allows access tokens issued under one redeemer-specific policy to
be used in the context of another redeemer.

Clients require the access token verification key before requesting a token. Clients SHOULD
NOT connect directly to the issuer to fetch any such keys. Instead, clients SHOULD use an
anonymizing request proxy such as OHTTP {{OHTTP}}.

# IANA Considerations {#iana}

This specification defines the following protocol messages, along with their
corresponding media types types:

- PolicyVerificationKey {{setup}}: "application/access-token-key"
- AccessTokenRequest {{issuance}}: "message/access-token-request"
- AccessTokenResponse {{issuance}}: "message/access-token-response"

The definition for each media type is in the following subsections.

## "application/access-token-key" media type

Type name:

: application

Subtype name:

: access-token-key

Required parameters:

: N/A

Optional parameters:

: None

Encoding considerations:

: only "8bit" or "binary" is permitted

Security considerations:

: see {{access-token-keys}}

Interoperability considerations:

: N/A

Published specification:

: this specification

Applications that use this media type:

: N/A

Fragment identifier considerations:

: N/A

Additional information:

: <dl>
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IESG

## "message/access-token-request" media type

Type name:

: message

Subtype name:

: access-token-request

Required parameters:

: N/A

Optional parameters:

: None

Encoding considerations:

: only "8bit" or "binary" is permitted

Security considerations:

: see {{issuance}}

Interoperability considerations:

: N/A

Published specification:

: this specification

Applications that use this media type:

: N/A

Fragment identifier considerations:

: N/A

Additional information:

: <dl>
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IESG

## "message/access-token-response" media type

Type name:

: message

Subtype name:

: access-token-response

Required parameters:

: N/A

Optional parameters:

: None

Encoding considerations:

: only "8bit" or "binary" is permitted

Security considerations:

: see {{issuance}}

Interoperability considerations:

: N/A

Published specification:

: this specification

Applications that use this media type:

: N/A

Fragment identifier considerations:

: N/A

Additional information:

: <dl>
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IESG

--- back
