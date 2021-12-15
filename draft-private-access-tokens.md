---
title: Private Access Tokens
abbrev: Private Access Tokens
docname: draft-private-access-tokens-latest
category: std

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: S. Hendrickson
    name: Scott Hendrickson
    org: Google LLC
    email: scott@shendrickson.com
 -
    ins: J. Iyengar
    name: Jana Iyengar
    org: Fastly
    email: jri@fastly.com
 -
    ins: T. Pauly
    name: Tommy Pauly
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: tpauly@apple.com
 -
    ins: S. Valdez
    name: Steven Valdez
    org: Google LLC
    email: svaldez@chromium.org
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    email: caw@heapingbits.net

--- abstract

This document defines a protocol for issuing and redeeming privacy-preserving
access tokens. These tokens can adhere to an issuance policy, allowing a
service to limit access according to the policy without tracking client identity.

--- middle

# Introduction {#introduction}

Servers commonly use passive and persistent identifiers associated with clients,
such as IP addresses or device identifiers, for enforcing access and usage
policies. For example, a server might limit the amount of content an IP address
can access over a given time period (referred to as a "metered paywall"), or
a server might rate-limit access from an IP address to prevent fraud and
abuse. Servers also commonly use the client's IP address as a strong indicator
of the client's geographic location to limit access to services or content to a
specific geographic area (referred to as "geofencing").

However, passive and persistent client identifiers can be used by any entity
that has access to it without the client's express consent. A server can use a
client's IP address or its device identifier to track client activity. A
client's IP address, and therefore its location, is visible to all entities on
the path between the client and the server. These entities can trivially track a
client, its location, and servers that the client visits.

A client that wishes to keep its IP address private can hide its IP address
using a proxy service or a VPN. However, doing so severely limits the client's
ability to access services and content, since servers might not be able to
enforce their policies without a stable and unique client identifier.

This document describes an architecture for Private Access Tokens (PATs),
using RSA Blind Signatures as defined in
{{!BLINDSIG=I-D.irtf-cfrg-rsa-blind-signatures}}, as an explicit replacement for
these passive client identifiers. These tokens are privately issued to clients
upon request and then redeemed by servers in such a way that the issuance and
redemption events for a given token are unlinkable.

At first glance, using PATs in lieu of passive identifiers for policy
enforcement suggests that some entity needs to know both the client's identity
and the server's policy, and such an entity would be trivially able to track a
client and its activities. However, with appropriate mediation and separation
between the parties involved in the issuance and the redemption protocols, it is
possible to eliminate this information concentration without any functional
regressions. This document describes such a protocol.

The relationship of this work to Privacy Pass ({{?I-D.ietf-privacypass-protocol}})
is discussed in {{privacy-pass}}.

## Motivation

This section describes classes of use cases where an origin would traditionally
use a stable and unique client identifier for enforcing attribute-based
policy. Hiding these identifiers from origins would therefore require an
alternative for origins to continue enforcing their policies. Using the Privacy
Address Token architecture for addressing these use cases is described in
{{examples}}.

### Rate-limited Access {#use-case-rate-limit}

An origin provides rate-limited access to content to a client over a fixed
period of time. The origin does not need to know the client's identity, but
needs to know that a requesting client has not exceeded the maximum rate set by
the origin.

One example of this use case is a metered paywall, where an origin limits the
number of page requests to each unique user over a period of time before the
user is required to pay for access. The origin typically resets this state
periodically, say, once per month. For example, an origin may serve ten (major
content) requests in a month before a paywall is enacted. Origins may want to
differentiate quick refreshes from distinct accesses.

Another example of this use case is rate-limiting page accesses to a client to
help prevent fraud. Operations that are sensitive to fraud, such as account
creation on a website, often employ rate-limiting as a defense in depth
strategy. Captchas or additional verification can be required by these pages
when a client exceeds a set rate-limit.

Origins routinely use client IP addresses for this purpose.

### Client Geo-Location {#use-case-geolocation}

An origin provides access to or customizes content based on the geo-location of
the client. The origin does not need to know the client's identity, but needs to
know the geo-location, with some level of accuracy, for providing service.

A specific example of this use case is "geo-fencing", where an origin restricts
the available content it can serve based on the client's geographical region.

Origins almost exclusively use client IP addresses for this purpose.

### Private Client Authentication {#use-case-authentication}

An origin provides access to content for clients that have been authorized by a
delegated or known mediator. The origin does not need to know the client's
identity.

A specific example of this use case is a federated service that authorizes users
for access to specific sites, such as a federated news service or a federated
video streaming service. The origin trusts the federator to authorize users and
needs proof that the federator authorized a particular user, but it does not
need the user's identity to provide access to content.

Origins could currently redirect clients to a federator for authentication, but
origins could then track the client's federator user ID or the client's IP
address across accesses.


## Architecture

At a high level, the PAT architecture seeks to solve the following problem: in
the absence of a stable Client identifier, an Origin needs to verify the
identity of a connecting Client and enforce access policies for the incoming
Client. To accomplish this, the PAT architecture employs four functional
components:

1. Client: requests a PAT from an Issuer and presents it to a Origin for access
   to the Origin's service.

1. Mediator: authenticates a Client, using information such as its IP address,
   an account name, or a device identifier. Anonymizes a Client to an Issuer and
   relays information between an anonymized Client and an Issuer.

1. Issuer: issues PATs to an anonymized Client on behalf of an
   Origin. Anonymizes an Origin to a Mediator and enforces the Origin's policy.

1. Origin: directs a Client to an Issuer with a challenge and enables access to
   content or services to the Client upon verification of any PAT sent in
   response by the Client.

In the PAT architecture, these four components interact as follows.

An Origin designates a trusted Issuer to issue tokens for it. The Origin then
redirects any incoming Clients to the Issuer for policy enforcement, expecting
the Client to return with a proof from the Issuer that the Origin's policy has
been enforced for this Client.

The Client employs a trusted Mediator through which it communicates with the
Issuer for this proof. The Mediator performs three important functions:

- authenticate and associate the Client with a stable identifier;

- maintain issuance state for the Client and relay it to the Issuer; and

- anonymize the Client and mediate communication between the Client and the
  Issuer.

When a Mediator-anonymized Client requests a token from an Issuer, the Issuer
enforces the Origin's policies based on the received Client issuance state and
Origin policy. Issuers know the Origin's policies and enforce them on behalf of the
Origin. An example policy is: "Limit 10 accesses per Client".  More examples and
their use cases are discussed in {{examples}}. The Issuer does not learn the
Client's true identity.

Finally, the Origin provides access to content or services to a Client upon
verifying a PAT presented by the Client. Verification of this
token serves as proof that the Client meets the Origin's policies as enforced by
the delegated Issuer with the help of a Mediator. The Origin can then provide
any services or content gated behind these policies to the Client.

{{fig-overview}} shows the components of the PAT architecture described in this
document. Protocol details follow in {{challenge-redemption}} and {{issuance}}.

~~~
 Client        Mediator          Issuer          Origin

    <---------------------------------------- Challenge \
                                                        |
+--------------------------------------------\          |
| TokenRequest --->                          |          |
|             (validate)                     |          |
|             (attach state)                 |          |
|                    TokenRequest --->       |          |    PAT
|                                 (validate) |   PAT    | Challenge/
|                                 (evaluate) | Issuance |  Response
|                    <--- TokenResponse      |   Flow   |   Flow
|             (evaluate)                     |          |
|             (update state)                 |          |
|   <--- TokenResponse                       |          |
---------------------------------------------/          |
                                                        |
     Response -------------------------------------- >  /
~~~
{: #fig-overview title=" PAT Architectural Components"}


## Properties and Requirements {#properties}

In this architecture, the Mediator, Issuer, and Origin each have partial
knowledge of the Client's identity and actions, and each entity only knows
enough to serve its function (see {{terms}} for more about the pieces of
information):

- The Mediator knows the Client's identity and learns the Client's public key
  (CLIENT_KEY), the Issuer being targeted (ISSUER_NAME), the period of time
  for which the Issuer's policy is valid (ISSUER_POLICY_WINDOW), and the number
  of tokens issued to a given Client for the claimed Origin in the given policy
  window.  The Mediator does not know the identity of the Origin the Client is
  trying to access (ORIGIN_ID), but knows a Client-anonymized identifier for
  it (ANON_ORIGIN_ID).

- The Issuer knows the Origin's secret (ORIGIN_SECRET) and policy about client
  access, and learns the Origin's identity (ORIGIN_NAME) and the number of
  previous tokens issued to the Client (as communicated by the Mediator) during
  issuance. The Issuer does not learn the Client's identity.

- The Origin knows the Issuer to which it will delegate an incoming Client
  (ISSUER_NAME), and can verify that any tokens presented by the Client were
  signed by the Issuer. The Origin does not learn which Mediator was used by a
  Client for issuance.

Since an Issuer enforces policies on behalf of Origins, a Client is required to
reveal the Origin's identity to the delegated Issuer. It is a requirement of
this architecture that the Mediator not learn the Origin's identity so that,
despite knowing the Client's identity, a Mediator cannot track and concentrate
information about Client activity.

An Issuer expects a Mediator to verify its Clients' identities correctly, but an
Issuer cannot confirm a Mediator's efficacy or the Mediator-Client relationship
directly without learning the Client's identity. Similarly, an Origin does not
know the Mediator's identity, but ultimately relies on the Mediator to correctly
verify or authenticate a Client for the Origin's policies to be correctly
enforced. An Issuer therefore chooses to issue tokens to only known and
reputable Mediators; the Issuer can employ its own methods to determine the
reputation of a Mediator.

A Mediator is expected to employ a stable Client identifier, such as an IP
address, a device identifier, or an account at the Mediator, that can serve as a
reasonable proxy for a user with some creation and maintenance cost on the user.

For the Issuance protocol, a Client is expected to create and maintain stable
and explicit secrets for time periods that are on the scale of Issuer policy
windows. Changing these secrets arbitrarily during a policy window can result in
token issuance failure for the rest of the policy window; see {{client-state}}
for more details. A Client can use a service offered by its Mediator or a
third-party to store these secrets, but it is a requirement of the PAT
architecture that the Mediator not be able to learn these secrets.

The privacy guarantees of the PAT architecture, specifically those around
separating the identity of the Client from the names of the Origins that it
accesses, are based on the expectation that there is not collusion between
the entities that know about Client identity and those that know about Origin
identity. Clients choose and share information with Mediators, and Origins
choose and share policy with Issuers; however, the Mediator is generally
expected to not be colluding with Issuers or Origins. If this occurs, it
can become possible for a Mediator to learn or infer which Origins a
Client is accessing, or for an Origin to learn or infer the Client
identity. For further discussion, see {{collusion}}.

## Client Identity

The PAT architecture does not enforce strong constraints around the definition
of a Client identity and allows it to be defined entirely by a Mediator. If a
user can create an arbitrary number of Client identities that are accepted by
one or more Mediators, a malicious user can easily abuse the system to
defeat the Issuer's ability to enforce per-Client policies.

These multiple identities could be fake or true identities.

A Mediator alone is responsible for detecting and weeding out fake Client
identities in the PAT architecture. An Issuer relies on a Mediator's reputation;
as explained in {{properties}}, the correctness of the architecture hinges on
Issuers issuing tokens to only known and reputable Mediators.

Users have multiple true identities on the Internet however, and as a result, it
seems possible for a user to abuse the system without having to create
fake identities. For instance, a user could use multiple Mediators,
authenticating with each one using a different true identity.

The PAT architecture offers no panacea against this potential abuse.  We note
however that the usages of PATs will cause the ecosystem to evolve and offer
practical mitigations, such as:

- An Issuer can learn the properties of a Mediator - specifically, which stable
  Client identifier is authenticated by the Mediator - to determine whether the
  Mediator is acceptable for an Origin.

- An Origin can choose an Issuer based on the types of Mediators accepted by the
  Issuer, or the Origin can communicate its constraints to the designated
  Issuer.

- An Origin can direct a user to a specific Issuer based on client properties
  that are visible. For instance, properties that are observable in the HTTP
  User Agent string.

- The number of true Mediator-authenticated identities for a user is expected to
  be small, and therefore likely to be small enough to not matter for certain
  use cases. For instance, when PATs are used to prevent fraud by rate-limiting
  Clients (as described in {{use-case-rate-limit}}), an Origin might be tolerant
  of the potential amplification caused by an attacking user's access to
  multiple true identities with Issuer-trusted Mediators.


## User Interaction

When used in contexts like websites, origin servers that challenge clients for
Private Access Tokens need to consider how to optimize their interaction model
to ensure a good user experience.

Private Access Tokens are designed to be used without explicit user involvement.
Since tokens are only valid for a single origin and in response to a specific
challenge, there is no need for a user to manage a limited pool of tokens
across origins. The information that is available to an origin upon token
redemption is limited to the fact that this is a client that passed a
Mediator's checks and has not exceeded the per-origin limit defined by an
Issuer. Generally, if a user is willing to use Private Access Tokens with
a particular origin (or all origins), there is no need for per-challenge
user interaction. Note that the Issuance flow may separately involve user interaction if
the Mediator needs to authenticate the Client.

Since tokens are issued using a separate connection through a Mediator
to an Issuer, the process of issuance can add user-perceivable latency.
Origins SHOULD NOT block useful work on token authentication.
Instead, token authentication can be used in similar ways to CAPTCHA
validation today, but without the need for user interaction. If issuance
is taking a long time, a website could show an indicator that it is waiting,
or fall back to another method of user validation.

If an origin is requesting an unexpected number of tokens, such as requesting
token authentication more than once for a single website load, it can indicate
that the server is not functioning correctly, or is trying to attack or overload
the client or issuance servers. In such cases, the client SHOULD ignore
redundant token challengers, or else alert the user.


# Notation and Terminology {#terms}

{::boilerplate bcp14}

Unless said otherwise, this document encodes protocol messages in TLS notation
from {{!TLS13=RFC8446}}, Section 3.

This draft includes pseudocode that uses the functions and conventions defined
in {{!HPKE=I-D.irtf-cfrg-hpke}}.

Encoding an integer to a sequence of bytes in network byte order is described
using the function "encode(n, v)", where "n" is the number of bytes and "v" is
the integer value. The function "len()" returns the length of a sequence of bytes.

The following terms are defined to refer to the different pieces of information
passed through the system:

ISSUER_NAME:
: The Issuer Name identifies which Issuer is able to provide tokens for a Client.
The Client sends the Issuer Name to the Mediator so the Mediator know where to
forward requests. Each Issuer is associated with a specific ISSUER_POLICY_WINDOW.

ISSUER_POLICY_WINDOW:
: The period over which an Issuer will track access policy, defined in terms of
seconds and represented as a uint64. The state that the Mediator keeps for a Client
is specific to a policy window. The effective policy window for a specific Client
starts when the Client first sends a request associated with an Issuer.

ORIGIN_TOKEN_KEY:
: The public key used when generating and verifying Private Access Tokens. Each
Origin Token Key is unique to a single Origin. The corresponding private key
is held by the Issuer.

ISSUER_KEY:
: The public key used to encrypt values such as ORIGIN_NAME in requests from
Clients to the Issuer, so that Mediators cannot learn the ORIGIN_NAME value. Each
ISSUER_KEY is used across all requests on the Issuer, for different Origins.

ORIGIN_NAME:
: The name of the Origin that requests and verifies Private Access Tokens.

ANON_ORIGIN_ID:
: An identifier that is generated by the Client and marked on requests to the
Mediator, which represents a specific Origin anonymously. The Client generates
a stable ANON_ORIGIN_ID for each ORIGIN_NAME, to allow the Mediator to count
token access without learning the ORIGIN_NAME.

CLIENT_KEY:
: A public key chosen by the Client and shared only with the Mediator.

CLIENT_SECRET:
: The secret key used by the Client during token issuance, whose public key
(CLIENT_KEY) is shared with the Mediator.

ORIGIN_SECRET:
: The secret key used by the Issuer during token issuance, whose public key is
not shared with anyone.

ANON_ISSUER_ORIGIN_ID:
: An identifier that is generated by Issuer based on an ORIGIN_SECRET that is
per-Client and per-Origin. See {{response-two}} for details of derivation.

# Configuration {#setup}

Issuers MUST provide three parameters for configuration:

1. ISSUER_KEY: a `KeyConfig` as defined in {{!OHTTP=I-D.thomson-http-oblivious}} to use when
   encrypting the ORIGIN_NAME in issuance requests. This parameter uses resource media type
   "application/ohttp-keys".
1. ISSUER_POLICY_WINDOW: a uint64 of seconds as defined in {{terms}}.
1. ISSUER_REQUEST_URI: a Private Access Token request URL for generating access tokens.
   For example, an Issuer URL might be https://issuer.example.net/access-token-request. This parameter
   uses resource media type "text/plain".

These parameters can be obtained from an Issuer via a directory object, which is a JSON
object whose field names and values are raw values and URLs for the parameters.

| Field Name           | Value                                            |
|:---------------------|:-------------------------------------------------|
| issuer-key           | ISSUER_KEY resource URL as a JSON string         |
| issuer-policy-window | ISSUER_POLICY_WINDOW as a JSON number            |
| issuer-request-uri   | ISSUER_REQUEST_URI resource URL as a JSON string |


As an example, the Issuer's JSON directory could look like:

~~~
 {
    "issuer-key": "https://issuer.example.net/key",
    "issuer-token-window": 86400,
    "issuer-request-uri": "https://issuer.example.net/access-token-request"
 }
~~~

Mediators MUST provide a single parameter for configuration, MEDIATOR_REQUEST_URI,
wich is Private Access Token request URL for proxying protocol messages to Issuers.
For example, a Mediator URL might be https://mediator.example.net/relay-access-token-request.
Similar to Issuers, Mediators make this parameter available by a directory object
with the following contents:

| Field Name           | Value                             |
|:---------------------|:----------------------------------|
| mediator-request-uri | MEDIATOR_REQUEST_URI resource URL |


As an example, the Mediator's JSON dictionary could look like:

~~~
 {
    "mediator-request-uri": "https://mediator.example.net/relay-access-token-request."
 }
~~~

Issuer and Mediator directory resources have the media type "application/json"
and are located at the well-known location /.well-known/private-access-tokens-directory.

# Token Challenge and Redemption Protocol {#challenge-redemption}

This section describes the interactive protocol for the token challenge
and redemption flow between a Client and an Origin.

Token redemption is performed using HTTP Authentication ({{!RFC7235}}), with
the scheme "PrivateAccessToken". Origins challenge Clients to present a unique,
single-use token from a specific Issuer. Once a Client has received a token
from that Issuer, it presents the token to the Origin.

Token redemption only requires Origins to verify token signatures computed
using the Blind Signature protocol from {{!BLINDSIG}}. Origins are not required
to implement the complete Blind Signature protocol. (In contrast, token issuance
requires Clients and Issuers to implement the Blind Signature protocol, as
described in {{issuance}}.)

## Token Challenge {#challenge}

Origins send a token challenge to Clients in an "WWW-Authenticate" header with
the "PrivateAccessToken" scheme. This challenge includes a TokenChallenge message,
along with information about what keys to use when requesting a token from
the Issuer.

The TokenChallenge message has the following structure:

~~~
struct {
    uint8_t version;
    opaque origin_name<1..2^16-1>;
    opaque issuer_name<1..2^16-1>;
    opaque redemption_nonce[32];
} TokenChallenge;
~~~

The structure fields are defined as follows:

- "version" is a 1-octet integer. This document defines version 1.

- "origin_name" is a string containing the name of the Origin (ORIGIN_NAME).

- "issuer_name" is a string containing the name of the Issuer (ISSUER_NAME).

- "redemption_nonce" is a fresh 32-byte nonce generated for each redemption request.

When used in an authentication challenge, the "PrivateAccessToken" scheme uses the
following attributes:

- "challenge", which contains a base64url-encoded {{!RFC4648}} TokenChallenge
value. This MUST be unique for every 401 HTTP response to prevent replay attacks.

- "token-key", which contains a base64url encoding of the SubjectPublicKeyInfo object
for use with the RSA Blind Signature protocol (ORIGIN_TOKEN_KEY).

- "issuer-key", which contains a base64url encoding of a `KeyConfig` as defined
in {{OHTTP}} to use when encrypting the ORIGIN_NAME in issuance requests
(ISSUER_KEY).

- "max-age", an optional attribute that consists of the number of seconds for which
the challenge will be accepted by the Origin.

Origins MAY also include the standard "realm" attribute, if desired.

As an example, the WWW-Authenticate header could look like this:

~~~
WWW-Authenticate: PrivateAccessToken challenge=abc..., token-key=123...,
issuer-key=456...
~~~

Upon receipt of this challenge, a Client uses the message and keys in the Issuance protocol
(see {{issuance}}). If the TokenChallenge has a version field the Client
does not recognize or support, it MUST NOT parse or respond to the challenge.
This document defines version 1, which indicates use of private tokens based on
RSA Blind Signatures {{BLINDSIG}}, and determines the rest of the structure contents.

Note that it is possible for the WWW-Authenticate header to include multiple
challenges, in order to allow the Client to fetch a batch of multiple tokens
for future use.

For example, the WWW-Authenticate header could look like this:

~~~
WWW-Authenticate: PrivateAccessToken challenge=abc..., token-key=123...,
issuer-key=456..., PrivateAccessToken challenge=def..., token-key=234...,
issuer-key=567...
~~~

## Token Redemption {#redemption}

The output of the issuance protocol is a token that corresponds to the Origin's challenge (see {{challenge}}).
A token is a structure that begins with a single byte that indicates a version, which
MUST match the version in the TokenChallenge structure.

~~~
struct {
    uint8_t version = 0x01;
    uint8_t token_key_id[32];
    uint8_t message[32];
    uint8_t signature[Nk];
} Token;
~~~

The structure fields are defined as follows:

- "version" is a 1-octet integer. This document defines version 1.

- "token_key_id" is a collision-resistant hash that identifies the ORIGIN_TOKEN_KEY
used to produce the signature. This is generated as SHA256(public_key), where
public_key is a DER-encoded SubjectPublicKeyInfo object carrying the public key.

- "message" is a 32-octet message containing the hash of the original
TokenChallenge, SHA256(TokenChallenge). This message is signed by the signature,

- "signature" is a Nk-octet RSA Blind Signature that covers the message. For
version 1, Nk is indicated by size of the Token structure and may be 256, 384,
or 512. These correspond to RSA 2048, 3072, and 4096 bit keys. Clients implementing
version 1 MUST support signature sizes with Nk of 512 and 256.

When used for client authorization, the "PrivateAccessToken" authentication
scheme defines one parameter, "token", which contains the base64url-encoded
Token struct. All unknown or unsupported parameters to "PrivateAccessToken"
authentication credentials MUST be ignored.

Clients present this Token structure to Origins in a new HTTP request using
the Authorization header as follows:

~~~
Authorization: PrivateAccessToken token=abc...
~~~

Origins verify the token signature using the corresponding policy verification
key from the Issuer, and validate that the message matches the hash of a
TokenChallenge it previously issued and is still valid, SHA256(TokenChallenge),
and that the version of the Token matches the version in the TokenChallenge.
The TokenChallenge MAY be bound to a specific HTTP session with Client, but
Origins can also accept tokens for valid challenges in new sessions.

If a Client's issuance request fails with a 401 error, as described in {{request-two}},
the Client MUST react to the challenge as if it could not produce a valid Authorization
response.


# Issuance Protocol {#issuance}

This section describes the Issuance protocol for a Client to request and receive
a token from an Issuer. Token issuance involves a Client, Mediator, and Issuer,
with the following steps:

1. The Client sends a token request containing a token request, encrypted origin
   name, and one-time-use public key and signature to the Mediator

1. The Mediator validates the request contents, specifically checking the request
   signature, and proxies the request to the Issuer

1. The Issuer validates the request against the signature, and processes its contents,
   and produces a token response sent back to the Mediator

1. The Mediator verifies the response and proxies the response to the Client

The Issuance protocol has a number of underlying cryptographic dependencies for
operation:

- {{HPKE}}, for encrypting information in transit between Client and Issuer across the Mediator.

- RSA Blind Signatures {{BLINDSIG}}, for issuing and constructing Tokens as described in {{redemption}}.

- Ed25519 signatures, as described in {{!RFC8032}}, for verifying correctness of Client requests.

Clients and Issuers are required to implement all of these dependencies, whereas Mediators are required
to implement Ed25519 signature support.

## State Requirements

The Issuance protocol requires each participating endpoint to maintain some
necessary state, as described in this section.

### Client State {#client-state}

A Client is required to have the following information, derived from a given TokenChallenge:

- Origin name (ORIGIN_NAME), a URI referring to the Origin {{!RFC6454}}. This is
  the value of TokenChallenge.origin_name.
- Origin token public key (ORIGIN_TOKEN_KEY), a blind signature public key
  corresponding to the Origin identified by TokenChallenge.origin_name.
- Issuer public key (ISSUER_KEY), a public key used to encrypt requests
  corresponding to the Issuer identified by TokenChallenge.issuer_name.

Clients maintain a stable CLIENT_KEY that they use for all communication with
a specific Mediator. CLIENT_KEY is a public key, where the corresponding private key
CLIENT_SECRET is known only to the client.

If the client loses this (CLIENT_KEY, CLIENT_SECRET), they may generate a new tuple. The
mediator will enforce if a client is allowed to use this new CLIENT_KEY. See {{mediator-state}}
for details on this enforcement.

Clients also need to be able to generate an ANON_ORIGIN_ID value that corresponds
to the ORIGIN_NAME, to send in requests to the Mediator.

ANON_ORIGIN_ID MUST be a stable and unpredictable 32-byte value computed by the Client.
Clients MUST NOT change this value across token requests for the same ORIGIN_NAME. Doing
so will result in token issuance failure (specifically, when a Mediator rejects a request
upon detecting two ANON_ORIGIN_ID values that map to the same Origin).

One possible mechanism for implementing this identifier is for the Client to store a mapping
between the ORIGIN_NAME and a randomly generated ANON_ORIGIN_ID for future requests. Alternatively,
the Client can compute a PRF keyed by a per-client secret (CLIENT_SECRET) over the ORIGIN_NAME,
e.g., ANON_ORIGIN_ID = HKDF(secret=CLIENT_SECRET, salt="", info=ORIGIN_NAME).

### Mediator State {#mediator-state}

A Mediator is required to maintain state for every authenticated Client. The mechanism
of identifying a Client is specific to each Mediator, and is not defined in this document.
As examples, the Mediator could use device-specific certificates or account authentication
to identify a Client.

Mediators must enforce that Clients don't change their CLIENT_KEY frequently, to ensure Clients can't
regularily evade the per-client policy as seen by the issuer. Mediators MUST NOT allow Clients to
change their CLIENT_KEY more than once within a policy window, or in the subsequent policy window
after a previous CLIENT_KEY change. Alternative schemes where the mediator stores the encrypted
(CLIENT_KEY, CLIENT_SECRET) tuple on behalf of the client are possble but not described here.

Mediators are expected to know the ISSUER_POLICY_WINDOW for any ISSUER_NAME to which
they allow access. This information can be retrieved using the URIs defined in {{setup}}.

For each Client-Issuer pair, a Mediator maintains a policy window
start and end time for each Issuer from which a Client requests a token.

For each tuple of (CLIENT_KEY, ANON_ORIGIN_ID, policy window), the Mediator maintains the
following state:

- A counter of successful tokens issued
- Whether or not a previous request was rejected by the Issuer
- The last received ANON_ISSUER_ORIGIN_ID value for this ANON_ORIGIN_ID, if any

### Issuer State {#issuer-state}

Issuers maintain a stable ORIGIN_SECRET that they use in calculating values returned
to the Mediator for each origin. If this value changes, it will open up a possibility
for Clients to request extra tokens for an Origin without being limited, within a
policy window.

Issuers are expected to have the private key that corresponds to ISSUER_KEY,
which allows them to decrypt the ORIGIN_NAME values in requests.

Issuers also need to know the set of valid ORIGIN_TOKEN_KEY public keys and corresponding
private key, for each ORIGIN_NAME that is served by the Issuer. Origins SHOULD update
their view of the ORIGIN_TOKEN_KEY regularly to ensure that Client requests do not fail
after ORIGIN_TOKEN_KEY rotation.

## Issuance HTTP Headers

The Issuance protocol defines four new HTTP headers that are used in requests
and responses between Clients, Mediators, and Issuers (see {{iana-headers}}).

The "Sec-Token-Origin" is an Item Structured Header {{!RFC8941}}. Its
value MUST be a Byte Sequence. This header is sent both on Client-to-Mediator
requests ({{request-one}}) and on Issuer-to-Mediator responses ({{response-one}}).
Its ABNF is:

~~~
    Sec-Token-Origin = sf-binary
~~~

The "Sec-Token-Client" is an Item Structured Header {{!RFC8941}}. Its
value MUST be a Byte Sequence. This header is sent on Client-to-Mediator
requests ({{request-one}}), and contains the bytes of CLIENT_KEY.
Its ABNF is:

~~~
    Sec-Token-Client = sf-binary
~~~

The "Sec-Token-Nonce" is an Item Structured Header {{!RFC8941}}. Its
value MUST be a Byte Sequence. This header is sent on Client-to-Mediator
requests ({{request-one}}), and contains a per-request nonce value.
Its ABNF is:

~~~
    Sec-Token-Nonce = sf-binary
~~~

The "Sec-Token-Count" is an Item Structured Header {{!RFC8941}}. Its
value MUST be an Integer. This header is sent on Mediator-to-Issuer
requests ({{request-one}}), and contains the number of times a
Client has previously received a token for an Origin. Its ABNF is:

~~~
    Sec-Token-Count = sf-integer
~~~

## Client-to-Mediator Request {#request-one}

The Client and Mediator MUST use a secure and Mediator-authenticated HTTPS
connection. They MAY use mutual authentication or mechanisms such as TLS
certificate pinning, to mitigate the risk of channel compromise; see
{{sec-considerations}} for additional about this channel.

Issuance begins by Clients hashing the TokenChallenge to produce a token input
as `message = SHA256(challenge)`, and then blinding `message` as follows:

~~~
blinded_req, blind_inv = rsabssa_blind(ORIGIN_TOKEN_KEY, message)
~~~

The Client MUST use a randomized variant of RSABSSA in producing this signature
with a salt length of at least 32 bytes.

The Client then uses CLIENT_KEY to generate its one-time-use request public
key `request_key` and blind `request_key_blind` as described in {{client-stable-mapping}}.

The Client then encrypts the origin name using ISSUER_KEY, producing
`issuer_key_id` and `encrypted_origin_name` as described in {{encrypt-origin}}.

Finally, the Client uses CLIENT_SECRET to produce `request_signature`
as described in {{index-proof}}.

The Client then constructs a Private Access Token request with the following
contents:

~~~
struct {
   uint8_t version = 0x01;
   uint8_t token_key_id;
   uint8_t blinded_req[Nk];
   uint8_t request_key[32];
   uint8_t issuer_key_id[32];
   uint8_t encrypted_origin_name<1..2^16-1>;
   uint8_t request_signature[64];
} AccessTokenRequest;
~~~

The structure fields are defined as follows:

- "version" is a 1-octet integer, which matches the version in the TokenChallenge.
This document defines version 1.

- "token_key_id" is the least significant byte of the ORIGIN_TOKEN_KEY key ID, which is
generated as SHA256(public_key), where public_key is a DER-encoded SubjectPublicKeyInfo
object carrying ORIGIN_TOKEN_KEY.

- "blinded_req" is the Nk-octet request defined above.

- "request_key" is computed as described in {{index-request}}.

- "issuer_key_id" is a collision-resistant hash that identifies the ISSUER_KEY public
key, generated as SHA256(KeyConfig).

- "encrypted_origin_name" is an encrypted structure that contains ORIGIN_NAME,
calculated as described in {{encrypt-origin}}.

- "request_signature" is computed as described in {{index-proof}}.

The Client then generates an HTTP POST request to send through the Mediator to
the Issuer, with the AccessTokenRequest as the body. The media type for this request
is "message/access-token-request". The Client includes the "Sec-Token-Origin" header,
whose value is ANON_ORIGIN_ID; the "Sec-Token-Client" header, whose value is CLIENT_KEY; and
the "Sec-Token-Nonce" header, whose value is request_key_blind. The Client
sends this request to the Mediator's proxy URI. An example request is shown below,
where Nk = 512.

~~~
:method = POST
:scheme = https
:authority = issuer.net
:path = /access-token-request
accept = message/access-token-response
cache-control = no-cache, no-store
content-type = message/access-token-request
content-length = 512
sec-token-origin = ANON_ORIGIN_ID
sec-token-client = CLIENT_KEY
sec-token-nonce = request_key_blind

<Bytes containing the AccessTokenRequest>
~~~

If the Mediator detects a version in the AccessTokenRequest that it does not recognize
or support, it MUST reject the request with an HTTP 400 error.

The Mediator also checks to validate that the issuer_key_id in the client's AccessTokenRequest
matches a known ISSUER_KEY public key for the Issuer. For example, the Mediator can
fetch this key using the API defined in {{setup}}. This check is done to help ensure that
the Client has not been given a unique key that could allow the Issuer to fingerprint or target
the Client. If the key does not match, the Mediator rejects the request with an HTTP
400 error. Note that Mediators need to be careful in cases of key rotation; see
{{privacy-considerations}}.

The Mediator finally checks to ensure that the AccessTokenRequest.request_key is valid
for the given CLIENT_KEY; see {{client-stable-mapping}} for verification details. If the
index is invalid, the Mediator rejects the request with an HTTP 400 error.

If the Mediator accepts the request, it will look up the state stored for this Client.
It will look up the count of previously generate tokens for this Client using the same
ANON_ORIGIN_ID. See {{mediator-state}} for more details.

If the Mediator has stored state that a previous request for this ANON_ORIGIN_ID was
rejected by the Issuer in the current policy window, it SHOULD reject the request without
forwarding it to the Issuer.

If the Mediator detects this Client has changed their CLIENT_KEY more frequently than allowed
as described in {{mediator-state}}, it SHOULD reject the request without forwarding it to
the Issuer.

## Mediator-to-Issuer Request {#request-two}

The Mediator and the Issuer MUST use a secure and Issuer-authenticated HTTPS
connection. Also, Issuers MUST authenticate Mediators, either via mutual
TLS or another form of application-layer authentication. They MAY additionally use
mechanisms such as TLS certificate pinning, to mitigate the risk of channel
compromise; see {{sec-considerations}} for additional about this channel.

Before copying and forwarding the Client's AccessTokenRequest request to the Issuer,
the Mediator validates the Client's stable mapping request as described in {{mediator-stable-mapping}}.
If this fails, the Mediator MUST return an HTTP 400 error to the Client. Otherwise, the
Mediator then adds a header that includes the count of previous tokens as "Sec-Token-Count".
The Mediator MAY also add additional context information, but MUST NOT add information
that will uniquely identify a Client.

~~~
:method = POST
:scheme = https
:authority = issuer.net
:path = /access-token-request
accept = message/access-token-response
cache-control = no-cache, no-store
content-type = message/access-token-request
content-length = 512
sec-token-count = 3

<Bytes containing the AccessTokenRequest>
~~~

Upon receipt of the forwarded request, the Issuer validates the following conditions:

- The "Sec-Token-Count" header is present
- The AccessTokenRequest contains a supported version
- For version 1, the AccessTokenRequest.issuer_key_id corresponds to the ID of the ISSUER_KEY held by the Issuer
- For version 1, the AccessTokenRequest.encrypted_origin_name can be decrypted using the
Issuer's private key (the private key associated with ISSUER_KEY), and matches
an ORIGIN_NAME that is served by the Issuer
- For version 1, the AccessTokenRequest.blinded_req is of the correct size
- For version 1, the AccessTokenRequest.token_key_id corresponds to an ID of an ORIGIN_TOKEN_KEY
for the corresponding ORIGIN_NAME

If any of these conditions is not met, the Issuer MUST return an HTTP 400 error to the Mediator,
which will forward the error to the client.

If the request is valid, the Issuer then can use the value from "Sec-Token-Count" to determine if
the Client is allowed to receive a token for this Origin during the current policy window. If the
Issuer refuses to issue more tokens, it responds with an HTTP 429 (Too Many Requests) error to the
Mediator, which will forward the error to the client.

The Issuer determines the correct ORIGIN_TOKEN_KEY by using the decrypted ORIGIN_NAME value and
AccessTokenRequest.token_key_id. If there is no ORIGIN_TOKEN_KEY whose truncated key ID matches
AccessTokenRequest.token_key_id, the Issuer MUST return an HTTP 401 error to Mediator, which will
forward the error to the client. The Mediator learns that the client's view of the Origin key
was invalid in the process.

## Issuer-to-Mediator Response {#response-one}

If the Issuer is willing to give a token to the Client, the Issuer decrypts
AccessTokenRequest.encrypted_origin_name to discover "origin". If this fails, the Issuer rejects
the request with a 400 error. Otherwise, the Issuer validates and processes the token request
with ORIGIN_SECRET corresponding to the designated Origin as described in {{issuer-stable-mapping}}.
If this fails, the Issuer rejects the request with a 400 error. Otherwise, the output is
index_result.

The Issuer completes the issuance flow by computing a blinded response as follows:

~~~
blind_sig = rsabssa_blind_sign(skP, AccessTokenRequest.blinded_req)
~~~

`skP` is the private key corresponding to ORIGIN_TOKEN_KEY, known only to the Issuer.

The Issuer generates an HTTP response with status code 200 whose body consists of
blind_sig, with the content type set as "message/access-token-response" and the
index_result set in the "Sec-Token-Origin" header.

~~~
:status = 200
content-type = message/access-token-response
content-length = 512
sec-token-origin = index_result

<Bytes containing the blind_sig>
~~~

## Mediator-to-Client Response {#response-two}

Upon receipt of a successful response from the Issuer, the Mediator extracts the
"Sec-Token-Origin" header, and uses the value to determine ANON_ISSUER_ORIGIN_ID
as described in {{mediator-stable-mapping}}.

If the "Sec-Token-Origin" is missing, or if the same ANON_ISSUER_ORIGIN_ID was previously
received in a response for a different ANON_ORIGIN_ID within the same policy window,
the Mediator MUST drop the token and respond to the client with an HTTP 400 status.
If there is not an error, the ANON_ISSUER_ORIGIN_ID is stored alongside the state
for the ANON_ORIGIN_ID.

For all other cases, the Mediator forwards all HTTP responses unmodified to the Client
as the response to the original request for this issuance.

When the Mediator detects successful token issuance, it MUST increment the counter
in its state for the number of tokens issued to the Client for the ANON_ORIGIN_ID.

Upon receipt, the Client handles the response and, if successful, processes the
body as follows:

~~~
sig = rsabssa_finalize(ORIGIN_TOKEN_KEY, nonce, blind_sig, blind_inv)
~~~

If this succeeds, the Client then constructs a Private Access Token as described in
{{challenge}} using the token input message and output sig.

## Encrypting Origin Names {#encrypt-origin}

Given a `KeyConfig` (ISSUER_KEY), Clients produce encrypted_origin_name and authenticate
contents of the AccessTokenRequest using the following values:

- the key identifier from the configuration, keyID, with the corresponding KEM identified by kemID,
the public key from the configuration, pkI, and;
- a selected combination of KDF, identified by kdfID, and AEAD, identified by aeadID.

Beyond the key configuration inputs, Clients also require the following inputs defined
in {{request-one}}: `token_key_id`, `blinded_req`, and `request_key`.

Together, these are used to encapsulate ORIGIN_NAME (`origin_name`) and produce
ENCRYPTED_ORIGIN_NAME (`encrypted_origin`) as follows:

1. Compute an {{HPKE}} context using pkI, yielding context and encapsulation key enc.
1. Construct associated data, aad, by concatenating the values of keyID, kemID, kdfID,
   aeadID, and all other values of the AccessTokenRequest structure.
1. Encrypt (seal) request with aad as associated data using context, yielding ciphertext ct.
1. Concatenate the values of aad, enc, and ct, yielding an Encapsulated Request enc_request.

Note that enc is of fixed-length, so there is no ambiguity in parsing this structure.

In pseudocode, this procedure is as follows:

~~~
enc, context = SetupBaseS(pkI, "AccessTokenRequest")
aad = concat(encode(1, keyID),
             encode(2, kemID),
             encode(2, kdfID),
             encode(2, aeadID),
             encode(1, version),
             encode(1, token_key_id),
             encode(Nk, blinded_req),
             encode(32, request_key),
             encode(32, issuer_key_id))
ct = context.Seal(aad, origin_name)
encrypted_origin_name = concat(enc, ct)
~~~

Issuers reverse this procedure to recover ORIGIN_NAME by computing the AAD as described
above and decrypting encrypted_origin_name with their private key skI, the private key
corresponding to pkI. In pseudocode, this procedure is as follows:

~~~
enc, ct = parse(encrypted_origin_name)
aad = concat(encode(1, keyID),
             encode(2, kemID),
             encode(2, kdfID),
             encode(2, aeadID),
             encode(1, version),
             encode(1, token_key_id),
             encode(Nk, blinded_req),
             encode(32, request_key),
             encode(32, issuer_key_id))
enc, context = SetupBaseR(enc, skI, "AccessTokenRequest")
origin_name, error = context.Open(aad, ct)
~~~

## Index Computation {#stable-mapping}

This section describes the Client, Mediator, and Issuer behavior in computing `index`,
the stable mapping based on client identity and origin name. At a high level,
this functionality computes y = F(x, k), where x is a per-Client secret and
k is a per-Origin secret, subject to the following constraints:

- The Mediator only learns y if the Client in possession of x engages with the protocol;
- The Mediator prevents a Client with private input x from running the protocol for input x' that is not equal to x;
- The Issuer does not learn x, nor does it learn when two requests correspond to the same private value x; and
- Neither the Client nor Mediator learn k.

The interaction between Client, Mediator, and Issuer in computing this
functionality is shown below.

~~~
Client               Mediator                Issuer
    (request, signature)
  ---------------------->
                           (request, signature)
                         ---------------------->
                                (response)
                         <----------------------
~~~

The protocol for computing this functionality is divided into sections for
each of the participants. {{client-stable-mapping}} describes Client behavior
for initiating the computation with its per-Client secret, {{mediator-stable-mapping}}
describes Mediator behavior for verifying Client requests, {{issuer-stable-mapping}}
describes Issuer behavior for computing the mapping with its per-Origin secret,
and {{mediator-output-stable-mapping}} describes the final Mediator step for
computing the mapping output.

The index computation is based on Ed25519 {{!RFC8032}}. It uses the following
functions based on this protocol:

- RandomScalar(): Generate a random Ed25519 scalar as per {{RFC8032, Section 5.1.5}}.
- ScalarMult(P, k): Multiply the Ed25519 public key P by scalar k, producing a new
  public key as a result.
- SerializeScalar(k): Serialize an Ed25519 scalar k, producing an opaque byte string
  as a result. DeserializeScalar(x) deserializes input byte string x into an Ed25519
  scalar, or fails with a "DeserializationError" otherwise.
- Ed25519-Sign(sk, msg): Sign input message msg using the Ed25519 private key sk,
  as defined in {{RFC8032, Section 5.1.6}}, producing an opaque byte string signature.
- Ed25519-Verify(pk, msg, sig): Verify the signature sig over input message msg against
  the Ed25519 public key pk, as defined in {{RFC8032, Section 5.1.7}}, producing a
  boolean value indicating success.

Multiplication of Ed25519 scalar values is denoted by '*'.

### Client Behavior {#client-stable-mapping}

This section describes the Client behavior for generating an one-time-use
request key and signature. Clients provide their secret CLIENT_KEY as input
to the request key generation step, and the rest of the token request inputs
to the signature generation step.

#### Request Key {#index-request}

Clients produce `request_key` by masking CLIENT_KEY and CLIENT_SECRET with a
randomly chosen blind as follows:

1. Generate a random Ed25519 scalar r.
1. Blind CLIENT_KEY and CLIENT_SECRET by r to compute a blinded key pair.
1. Serialize and output the blinded key and blind value, along with the
   blinded secret key.

In pseudocode, this is as follows:

~~~
blind = RandomScalar()
blind_secret = blind * CLIENT_SECRET
request_key = ScalarMult(CLIENT_KEY, blind)
request_key_blind = SerializeScalar(blind)
~~~

### Request Signature {#index-proof}

Clients produce signature of their request based on the following inputs defined in {{request-one}}:
`token_key_id`, `blinded_req`, `request_key`, `issuer_key_id`, `encrypted_origin_name`.
This process requires the `blind` and `blind_secret` values produced during
the {{index-request}} process, and works as follows:

1. Concatenate all signature inputs to yield a message to sign.
1. Compute an Ed25519 signature over the input message using the blinded secret key.
1. Output the signature.

In pseudocode, this is as follows:

~~~
context = concat(0x01, // version
                 token_key_id,
                 blinded_req,
                 request_key,
                 issuer_key_id,
                 encrypted_origin_name)
request_signature = Ed25519-Sign(blind_secret, context)
~~~

### Mediator Behavior (Client Request Validation) {#mediator-stable-mapping}

Given a client key (CLIENT_KEY), request_key_blind, and request_key,
Mediators verify the proof for correctness as follows:

1. Deserialize request_key_blind, yielding blind. If this fails, abort.
1. Parse the final 64 bytes of the request as request_signature. If this fails, abort.
1. Parse request_key and check if it's a valid public key. If this fails, abort.
1. Multiply CLIENT_KEY by blind, yielding a blinded key. If this does not match
   the blinded key from the request, abort.
1. Verify the request signature against request_key. If signature verification
   fails, abort.

In pseudocode, this is as follows:

~~~
// Parse and deserialize all client values
blind = DeserializeScalar(request_key_blind)
blind_key  = parse(request_key)
request_signature = parse(request_key[len(request_key)-64..])

// Verify the proof parameters against the client's public key
expected_blind_key = ScalarMult(CLIENT_KEY, blind)
if expected_blind_key != blind_key:
    raise InvalidParameterError

// Verify the siganture
context = parse(request_key[..len(request_key)-64])
valid = Ed25519-Verify(blind_key, context, request_signature)
if not valid:
   raise InvalidSignatureError
~~~

### Issuer Behavior {#issuer-stable-mapping}

Given a Client request request_key and Origin secret (ORIGIN_SECRET), Issuers
verify the request and compute a response as follows:

1. Parse the final 64 bytes of the request as request_signature. If this fails, abort.
1. Parse request_key as the blinded key and check if it's a valid Ed25519 public key. If this fails, abort.
1. Verify the request signature against the blinded key. If signature verification
   fails, abort.
1. Multiply the blinded key by ORIGIN_SECRET, yielding an index key.
1. Output the index key.

In pseudocode, this is as follows:

~~~
// Parse and deserialize all request values
blind_key  = parse(request_key)
request_signature = parse(request_key[len(request_key)-64..])

// Verify the proof
context = parse(request_key[..len(request_key)-64])
valid = Ed25519-Verify(blind_key, context, request_signature)
if not valid:
   raise InvalidSignatureError

// Evaluate the request with the per-Origin secret
index_key = ScalarMult(blind_key, ORIGIN_SECRET)
~~~

### Mediator Behavior (Mapping Output Computation) {#mediator-output-stable-mapping}

Given an Issuer response index_key, Client blind, and Client public
key (CLIENT_KEY), Mediators complete the mapping computation as follows:

1. Check that index_key is a valid Ed25519 public key. If this fails, abort.
1. Multiply the index key by the multiplicative inverse of the Client blind, yielding the index result.
1. Run HKDF {{!RFC5869}} with the index result as the secret, CLIENT_KEY as the salt, and
   ASCII string "ANON_ISSUER_ORIGIN_ID" as the info string, yielding ANON_ISSUER_ORIGIN_ID.
1. Output ANON_ISSUER_ORIGIN_ID.

In pseudocode, this is as follows:

~~~
index_result = ScalarMult(index_key, blind^(-1))
ANON_ISSUER_ORIGIN_ID = HKDF(secret=index_result,
                             salt=CLIENT_KEY,
                             info="ANON_ISSUER_ORIGIN_ID")
~~~

# Instantiating Uses Cases {#examples}

This section describes various instantiations of this protocol to address use cases
described in {{motivation}}.

## Rate-limited Access {#implement-rate-limit}

To instantiate this case, the site acts as an Origin and registers a "bounded token" policy
with the Issuer. In this policy, the Issuer enforces a fixed number of tokens that it will
allow a Client to request for a single ORIGIN_NAME.

Origins request tokens from Clients and, upon successful redemption, the Origin knows
the Client was able to request a token for the given ORIGIN_NAME within its budget.
Failure to present a token can be interpreted as a signal that the client's token
budget was exceeded.

Clients can redeem a token from a specific challenge up to the `max-age` in the challenge.
Servers can choose to issue many challenges in a single HTTP 401 response, providing the
client with many challenge nonces which can be used to redeem tokens over a longer period
of time.

## Client Geo-Location {#implement-geolocation}

To instantiate this use case, the Issuer has an issuing key pair per geographic region, i.e.,
each region has a unique policy key. When verifying the key for the Client request, the Mediator
obtains the per-region key from the Issuer based on the Client's perceived location. During
issuance, the Mediator checks that this key matches that of the Client's request. If it matches,
the Mediator forwards the request to complete issuance. The number of key pairs is then the cross
product of the number of Origins that require per-region keys and the number of regions.

During redemption, Clients present their geographic location to Origins in a "Sec-CH-Geohash"
header. Origins use this to obtain the appropriate policy verification key. Origins request
tokens from Clients and, upon successful redemption, the Origin knows the Client obtained a
token for the given ORIGIN_NAME in the specified region.

## Private Client Authentication {#implement-authentication}

To instantiate this case, the site acts as an Origin and registers an "unlimited token"
policy with the Issuer. In this policy, the Issuer does not enforce any limit on the number
of tokens a given user will obtain.

Origins request tokens from Clients and, upon successful redemption, the Origin knows
the Client was able to request a token for the given ORIGIN_NAME tuple. As a
result, the Origin knows this is an authentic client.

# Security Considerations {#sec-considerations}

This section discusses security considerations for the protocol.

[OPEN ISSUE: discuss trust model]

## Client Identity

The HTTPS connection between Client and Mediator is minimally Mediator-authenticated. Mediators
can also require Client authentication if they wish to restrict Private Access Token proxying
to trusted or otherwise authenticated Clients. Absent some form of Client authentication, Mediators
can use other per-Client information for the client identifier mapping, such as IP addresses.

## Denial of Service

Requesting and verifying a Private Access Token is more expensive than checking an implicit
signal, such as an IP address, especially since malicious clients can generate garbage
Private Access Tokens and for Origins to work. However, similar DoS vectors already exist
for Origins, e.g., at the underlying TLS layer.

## Channel Security

An attacker that can act as an intermediate between Mediator and Issuer
communication can influence or disrupt the ability for the Issuer to correctly
rate-limit token issuance.  All communication channels use server-authenticated
HTTPS. Some connections, e.g., between a Mediator and an Issuer, require
mutual authentication between both endpoints. Where appropriate, endpoints
MAY use further enhancements such as TLS certificate pinning to mitigate
the risk of channel compromise.

An attacker that can intermediate the channel between Client and Origin can
observe a TokenChallenge, and can view a Token being presented for authentication
to an Origin. Scoping the TokenChallenge nonce to the Client HTTP session prevents
Tokens being collected in one session and then presented to the Origin in another.
Note that an Origin cannot distinguish between a connection to a single Client and
a connection to an attacker intermediating multiple Clients. Thus, it is possible for
an attacker to collect and later present Tokens from multiple clients over the same
Origin session.

# Privacy Considerations {#privacy-considerations}

## Client Token State and Origin Tracking

Origins SHOULD only generate token challenges based on client action, such as when a user
loads a website. Clients SHOULD ignore token challenges if an Origin tries to force the
client to present tokens multiple times without any new client-initiated action. Failure
to do so can allow malicious origins to track clients across contexts. Specifically, an
origin can abuse per-user token limits for tracking by assigning each new client a random
token count and observing whether or not the client can successfully redeem that many
tokens in a given context. If any token redemption fails, then the origin learns information
about how many tokens that client had previously been issued.

By rejecting repeated or duplicative challenges within a single context, the origin only
learns a single bit of information: whether or not the client had any token quota left
in the given policy window.

## Origin Verification

Private Access Tokens are defined in terms of a Client authenticating to an Origin, where
the "origin" is used as defined in {{?RFC6454}}. In order to limit cross-origin correlation,
Clients MUST verify that the origin_name presented in the TokenChallenge structure ({{challenge}})
matches the origin that is providing the HTTP authentication challenge, where the matching logic
is defined for same-origin policies in {{?RFC6454}}. Clients MAY further limit which
authentication challenges they are willing to respond to, for example by only accepting
challenges when the origin is a web site to which the user navigated.

## Client Identification with Unique Keys

Client activity could be linked if an Origin and Issuer collude to have unique keys targeted
at specific Clients or sets of Clients.

To mitigate the risk of a targeted ISSUER_KEY, the Mediator can observe and validate
the issuer_key_id presented by the Client to the Issuer. As described in {{issuance}}, Mediators
MUST validate that the issuer_key_id in the Client's AccessTokenRequest matches a known public key
for the Issuer. The Mediator needs to support key rotation, but ought to disallow very rapid key
changes, which could indicate that an Origin is colluding with an Issuer to try to rotate the key
for each new Client in order to link the client activity.

To mitigate the risk of a targeted ORIGIN_TOKEN_KEY, the protocol expects that an Issuer has only
a single valid public key for signing tokens at a time. The Client does not present the issuer_key_id
of the token public key to the Issuer, but instead expects the Issuer to infer the correct key based
on the information the Issuer knows, specifically the origin_name itself.

## Collusion Among Different Entities {#collusion}

Collusion among the different entities in the PAT architecture can result in
violation of the Client's privacy.

Issuers and Mediators should be run by mutually distinct organizations to limit
information sharing. A single entity running an issuer and mediator for a single redemption
can view the origins being accessed by a given client. Running the issuer and mediator in
this 'single issuer/mediator' fashion reduces the privacy promises to those of the
{{?I-D.ietf-privacypass-protocol}}; see {{privacy-pass}} for more discussion. This may be
desirable for a redemption flow that is limited to specific issuers and mediators,
but should be avoided where hiding origins from the mediator is desirable.

If a Mediator and Origin are able to collude, they can correlate a client's identity and origin access patterns through timestamp correlation. The
timing of a request to an Origin and subsequent token issuance to a Mediator can reveal the Client
identity (as known to the Mediator) to the Origin, especially if repeated over multiple accesses.

# Deployment Considerations {#deploy}

## Origin Key Rollout

Issuers SHOULD generate a new (ORIGIN_TOKEN_KEY, ORIGIN_SECRET) regularly, and
SHOULD maintain old and new secrets to allow for graceful updates. The RECOMMENDED
rotation interval is two times the length of the policy window for that
information. During generation, issuers must ensure the `token_key_id` (the 8-bit
prefix of SHA256(ORIGIN_TOKEN_KEY)) is different from all other `token_key_id`
values for that origin currently in rotation. One way to ensure this uniqueness
is via rejection sampling, where a new key is generated until its `token_key_id` is
unique among all currently in rotation for the origin.

# IANA Considerations {#iana}

## Authentication Scheme

This document registers the "PrivateAccessToken" authentication scheme in the "Hypertext
Transfer Protocol (HTTP) Authentication Scheme Registry" established by {{!RFC7235}}.

Authentication Scheme Name: PrivateAccessToken

Pointer to specification text: {{challenge}} of this document

## HTTP Headers {#iana-headers}

This document registers four new headers for use on the token issuance path
in the "Permanent Message Header Field Names" <[](https://www.iana.org/assignments/message-headers)>.

~~~
    +-------------------+----------+--------+---------------+
    | Header Field Name | Protocol | Status |   Reference   |
    +-------------------+----------+--------+---------------+
    | Sec-Token-Origin  |   http   |  std   | This document |
    +-------------------+----------+--------+---------------+
    | Sec-Token-Client  |   http   |  std   | This document |
    +-------------------+----------+--------+---------------+
    | Sec-Token-Nonce   |   http   |  std   | This document |
    +-------------------+----------+--------+---------------+
    | Sec-Token-Count   |   http   |  std   | This document |
    +-------------------+----------+--------+---------------+
~~~
{: #iana-header-type-table title="Registered HTTP Header"}

## Media Types

This specification defines the following protocol messages, along with their
corresponding media types:

- AccessTokenRequest {{issuance}}: "message/access-token-request"
- AccessTokenResponse {{issuance}}: "message/access-token-response"

The definition for each media type is in the following subsections.

### "message/access-token-request" media type

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

### "message/access-token-response" media type

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

# Related Work: Privacy Pass {#privacy-pass}

Private Access Tokens has many similarities to the existing Privacy Pass protocol
({{?I-D.ietf-privacypass-protocol}}). Both protocols allow clients to redeem signed
tokens while not allowing linking between token issuance and token redemption.

There are several important differences between the protocols, however:

- Private Access Tokens uses per-origin tokens that support rate-limiting policies. Each
token can only be used with a specific origin in accordance with a policy defined for that
origin. This allows origins to implement metered paywalls or mechanisms that that limit the
actions a single client can perform. Per-origin tokens also ensure that one origin cannot
consume all of a client's tokens, so there is less need for clients to manage when they are
willing to present tokens to origins.

- Private Access Tokens employ an online challenge ({{challenge}}) during token redemption.
This ensures that tokens cannot be harvested and stored for use later. This also removes
the need for preventing double spending or employing token expiry techniques, such as
frequent signer rotation or expiry-encoded public metadata.

- Private Access Tokens use a publically verifiable signature
{{!BLINDSIG=I-D.irtf-cfrg-rsa-blind-signatures}} to optimize token
verification at the origin by avoiding a round trip to the issuer/mediator.
