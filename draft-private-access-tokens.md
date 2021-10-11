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
such as IP addresses or device identifiers, for enforcing client and usage
policies. For example, a server might limit access to the amount of content from
an IP address over a given time period (referred to as a "metered paywall"), or
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

This document describes an architecture that uses Private Access Tokens, using
RSA Blind Signatures as defined in
{{!BLINDSIG=I-D.irtf-cfrg-rsa-blind-signatures}}, as an explicit replacement for
these passive client identifiers. These tokens are privately issued to clients
upon request and then redeemed by servers in such a way that the issuance and
redemption events for a given token are unlinkable.

At first glance, using Private Access Tokens in lieu of passive identifiers for
policy enforcement suggests that some entity needs to know both the client's
identity and the server's policy, and such an entity would be trivially able to
track a client and its activities. However, with appropriate mediation and
separation between the parties involved in the issuance and the redemption
protocols, it is possible to eliminate this information concentration without
any functional regressions. This document describes such a protocol.


## Requirements

{::boilerplate bcp14}


# Motivation

This section describes classes of use cases where an origin would traditionally
use a stable and unique client identifier for enforcing attribute-based
policy. Hiding these identifiers from origins would therefore require an
alternative for origins to continue enforcing their policies. Using the Privacy
Address Token architecture for addressing these use cases is described in
{{examples}}.

## Rate-limited Access {#use-case-rate-limit}

An origin provides rate-limited access to content to a client over a fixed
period of time. The origin does not need to know the client's identity, but
needs to know that a requesting client has not exceeded the maximum rate set by
the origin.

One example of this use case is a metered paywall, where an origin limits the
number of page requests to each unique user over a period of time before the
user is required to pay for access. The origin typically resets this state
periodically, say, once per month. For example, an origin may serve ten (major
content) requests in a month before a paywall is enacted.

Another example of this use case is rate-limiting page accesses to a client to
help prevent fraud. Operations that are sensitive to fraud, such as account
creation on a website, often employ rate limiting as a defense in depth
strategy. Captchas or additional verification can be required by these pages
when a client exceeds a set rate limit.

Origins routinely use client IP addresses for this purpose.


## Client Geo-Location {#use-case-geolocation}

An origin provides access to or customizes content based on the geo-location of
the client. The origin does not need to know the client's identity, but needs to
know the geo-location, with some level of accuracy, for providing service.

A specific example of this use case is "geo-fencing", where an origin restricts
the available content it can serve based on the client's geographical region.

Origins almost exclusively use client IP addresses for this purpose.


## Private Client Authentication {#use-case-authentication}

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


# Overview

The architecture and protocol involves the following four entities:

1. Client: requests a Private Access Token from an Issuer and presents it to a
   Origin for access to the Origin's service.

1. Mediator: authenticates a Client, using information such as its IP address,
   an account name, or a device identifier. Anonymizes the Client and relays
   information between the anonymized Client and an Issuer.

1. Issuer: issues Private Access Tokens to an anonymized Client on behalf of a
   Origin. Enforces the Origin's policy.

1. Origin: verifies any Private Access Token sent by a Client and enables
   access to content or services to the Client upon verification.


The entities have the following properties:

1. A Mediator enforces and maintains a mapping between Client identifiers and
   Client-anonymized Origin identifiers;

1. An Issuer enforces the Origin's policies based on the received
   Mediator-anonymized Client identifier and Origin identifier, without
   learning the Client's true identity; and

1. An Origin provides access to content or services to a Client upon verifying
   the Client's Private Access Token, since the verification demonstrates that
   the Client access meets the Origin's policies.


The Mediator, Issuer, and Origin each have partial knowledge of the Client's
identity and actions, and each entity only knows enough to serve its
function. The pieces of information are identified in {{terms}}.

The Mediator knows the Client's identity, the Issuer being targeted
(ISSUER_NAME), and the period of time for which the Issuer's policy is valid
(ISSUER_POLICY_WINDOW). The Mediator does not know the identity of the Origin
the Client is trying to access (ORIGIN_NAME), but knows a Client-anonymized
identifier for it (ANON_ORIGIN_ID).

The Issuer knows the Origin's identity (ORIGIN_NAME), and the Origin's policy
about client access, but only sees the number of previous tokens issued to a
Client (as communicated by the Mediator), not the Client idenitity. Issuers
know the Origin's policies and enforce them on behalf of the Origin. An
example policy is: "Limit 10 accesses per Client". More examples and their use
cases are discussed in {{examples}}.

The Origin receives a Private Access Token from the client. Verification of
this token demonstrates to the Origin that the Client meets its policies
(since they were enforced by the Issuer before issuing this token), and then
provides the services or content gated behind these policies.

## Notation and Terminology {#terms}

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

CLIENT_ID:
: An identifier chosen by the Client and shared only with the Mediator.

CLIENT_SECRET:
: The secret key used by the Client during token issuance, whose public key is
shared with the Mediator.

ORIGIN_SECRET:
: The secret key used by the Issuer during token issuance, whose public key is
not shared with anyone.

ANON_ISSUER_ORIGIN_ID:
: An identifier that is generated by Issuer based on an ORIGIN_SECRET that is
per-Client and per-Origin. See {{response-two}} for details of derivation.

# API Endpoints {#setup}

Issuers MUST provide the following information available via the corresponding
API endpoints:

- ISSUER_KEY: /.well-known/issuer-key
- ISSUER_POLICY_WINDOW: /.well-known/issuer-policy

The content of issuer name public key is a `KeyConfig` as defined in {{!OHTTP=I-D.thomson-http-oblivious}}
to use when encrypting the ORIGIN_NAME in issuance requests. The response uses media type
"application/ohttp-keys".

The policy window (ISSUER_POLICY_WINDOW) is a resource of media type "application/json",
with the following structure:

~~~
{
   "access-token-window": <ISSUER_POLICY_WINDOW>
}
~~~

Issuers also advertise a Private Access Token request URL for generating access tokens.
For example, an Issuer URL might be https://issuer.net/access-token-request.

Mediators advertise a URL for proxying protocol messages to Issuers. For example,
a Mediator URL might be https://mediator.net/relay-access-token-request.

# Protocol

Private Access Tokens are single-use tokens cryptographically bound to
policies. Origins request tokens from Clients, who then engage with
Mediators and Issuers to private compute policy-compliant tokens and
reveal them to the Origin. Example policies and use cases that system
addresses are described in {{examples}}.

The rest of this section describes this interactive protocol in terms of
the token challenge and redemption flow ({{scheme}}) and corresponding token
issuance flow ({{issuance}}).

## Token Challenge and Redemption {#scheme}

Token redemption is performed using HTTP Authentication ({{!RFC7235}}), with
the scheme "PrivateAccessToken". Origins challenge Clients to present a unique,
single-use token from a specific Issuer. Once a Client has received a token
from that Issuer, it presents the token to the Origin.

### Token Challenge {#challenge}

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
WWW-Authenticate: PrivateAccessToken challenge=abc... token-key=123... issuer-key=456...
~~~

Upon receipt of this challenge, a Client uses the message and keys in the Issuance protocol
(see {{issuance}}). If the TokenChallenge has a version field the Client
does not recognize or support, it MUST NOT parse or respond to the challenge.
This document defines version 1, which indicates use of private tokens based on
RSA Blind Signatures {{BLINDSIG}}, and determines the rest of the structure contents.

### Token Redemption

The output of the issuance protocol is a token that corresponds to the Origin's challenge (see {{challenge}}).
A token is a structure that begins with a single byte that indicates a version, which
MUST match the version in the TokenChallenge structure.

~~~
struct {
    uint8_t version;
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

- "signature" is a Nk-octet RSA Blind Signature that covers the
message.  For version 1, Nk is indicated by size of the Token
structure and may be 256, 384, or 512.
These correspond to RSA 2048, 3072, and 4096 bit keys.
Clients implementing version 1 MUST support signature
sizes with Nk of 512 and 256.

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
key from the Issuer, and validate that the message matches the hash of the original
TokenChallenge for this session, SHA256(TokenChallenge), and that the version of the
Token matches the version in the TokenChallenge.

## Issuance {#issuance}

Token issuance involves a Client, Mediator, and Issuer, with the following steps:

1. The Client sends a token request to the Mediator, encrypted using an Issuer-specific key

1. The Mediator validates the request and proxies the request to the Issuer

1. The Issuer decrypts the request and sends a response back to the Mediator

1. The Mediator verifies the response and proxies the response to the Client

### Client State

Issuance assumes the Client has the following information, derived from a given TokenChallenge:

- Origin name (ORIGIN_NAME), a URI referring to the Origin {{!RFC6454}}. This is
  the value of TokenChallenge.origin_name.
- Origin token public key (ORIGIN_TOKEN_KEY), a blind signature public key
  corresponding to the Origin identified by TokenChallenge.origin_name.
- Issuer public key (ISSUER_KEY), a public key used to encrypt requests
  corresponding to the Issuer identified by TokenChallenge.issuer_name.

Clients maintain a stable CLIENT_ID that they use for all communication with
a specific Mediator. If this value changes, it will lead to token issuance
failures until policy window passes. CLIENT_ID is a public key, where the
corresponding private key CLIENT_SECRET is known only to the client.

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

Issuance requires Mediators to maintain state for each Client. The mechanism
of identifying a Client is specific to each Mediator, and is not defined in this document.
As examples, the Mediator could use device-specific certificates or account authentication
to identify a Client.

Mediators are expected to know the ISSUER_POLICY_WINDOW for any ISSUER_NAME to which
they allow access. This information can be retrieved using the URIs defined in {{setup}}.

For each Client-Issuer pair, a Mediator maintains a policy window
start and end time for each Issuer from which a Client requests a token.

For each tuple of (Client, ANON_ORIGIN_ID, policy window), the Mediator maintains the
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

Issuers also need to know the current ORIGIN_TOKEN_KEY public key and corresponding
private key, for each ORIGIN_NAME that is served by the Issuer.

### Issuance HTTP Headers

The issuance protocol defines four new HTTP headers that are used in requests
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
requests ({{request-one}}), and contains the bytes of CLIENT_ID.
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

### Client-to-Mediator Request {#request-one}

Issuance assumes that the Client and Mediator have a secure and
Mediator-authenticated HTTPS connection. See {{sec-considerations}} for additional
about this channel.

Issuance begins by Clients hashing the TokenChallenge to produce a token input
as message = SHA256(challenge), and then blinding message as follows:

~~~
blinded_req, blind_inv = rsabssa_blind(ORIGIN_TOKEN_KEY, message)
~~~

The Client MUST use a randomized variant of RSABSSA in producing this signature with
a salt length of at least 32 bytes.

The Client uses CLIENT_SECRET to generate "mapping_nonce", "mapping_key",
"mapping_generator", and "mapping_proof".

~~~
blind = RandomScalar()
blind_key = blind * CLIENT_SECRET
blind_generator = blind * Generator()
key_proof = SchnorrProof(CLIENT_SECRET, blind_key, blind_generator)
mapping_nonce = SerializeScalar(blind)
mapping_key = SerializeElement(blind_key)
mapping_generator = SerializeElement(blind_generator)
mapping_proof = SerializeProof(key_proof)
~~~

The Client then constructs a Private Access Token request using blinded_req,
mapping_key, mapping_generator, mapping_proof, and request_tag:

~~~
struct {
   uint8_t version;
   uint8_t key_id[32];
   uint8_t mapping_generator[Ne];
   uint8_t mapping_key[Ne];
   uint8_t mapping_proof[Np];
   uint8_t encrypted_origin_name<1..2^16-1>;
   uint8_t blinded_req[Nk];
} AccessTokenRequest;
~~~

The structure fields are defined as follows:

- "version" is a 1-octet integer, which matches the version in the TokenChallenge.
This document defines version 1.

- "key_id" is a collision-resistant hash that identifies the ISSUER_KEY public
key, generated as SHA256(KeyConfig).

- "mapping_generator", "mapping_key", and "mapping_proof" are computed as described above.

- "encrypted_origin_name" is an encrypted structure that contains ORIGIN_NAME,
calculated as described in {{encrypt-origin}}.

- "blinded_req" is the Nk-octet request defined above.

The Client then generates an HTTP POST request to send through the Mediator to
the Issuer, with the AccessTokenRequest as the body. The media type for this request
is "message/access-token-request". The Client includes the "Sec-Token-Origin" header,
whose value is ANON_ORIGIN_ID; the "Sec-Token-Client" header, whose value is CLIENT_ID; and
the "Sec-Token-Nonce" header, whose value is mapping_nonce. The Client sends this request
to the Mediator's proxy URI. An example request is shown below, where Nk = 512.

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
sec-token-client = CLIENT_ID
sec-token-nonce = mapping_nonce

<Bytes containing the AccessTokenRequest>
~~~

If the Mediator detects a version in the AccessTokenRequest that it does not recognize
or support, it MUST reject the request with an HTTP 400 error.

The Mediator also checks to validate that the key_id in the client's AccessTokenRequest
matches a known ISSUER_KEY public key for the Issuer. For example, the Mediator can
fetch this key using the API defined in {{setup}}. This check is done to help ensure that
the Client has not been given a unique key that could allow the Issuer to fingerprint or target
the Client. If the key does not match, the Mediator rejects the request with an HTTP
400 error. Note that Mediators need to be careful in cases of key rotation; see
{{privacy-considerations}}.

The Mediator finally checks to ensure that the AccessTokenRequest.mapping_proof is valid
for the given CLIENT_ID; see {{nizk-dl}} for verification details. If the index is invalid,
the Mediator rejects the request with an HTTP 400 error.

If the Mediator accepts the request, it will look up the state stored for this Client.
It will look up the count of previously generate tokens for this Client using the same
ANON_ORIGIN_ID. See {{mediator-state}} for more details.

If the Mediator has stored state that a previous request for this ANON_ORIGIN_ID was
rejected by the Issuer in the current policy window, it SHOULD reject the request without
forwarding it to the Issuer.

### Mediator-to-Issuer Request {#request-two}

Before copying and forwarding the Client's AccessTokenRequest request to the Issuer,
the Mediator adds a header that includes the count of previous tokens as "Sec-Token-Count".
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

Upon receipt of the forwarded request, the Issuer validates the following
conditions:

- The "Sec-Token-Count" header is present
- The AccessTokenRequest contains a supported version
- For version 1, the AccessTokenRequest.key_id corresponds to the ID of the ISSUER_KEY held by the Issuer
- For version 1, the AccessTokenRequest.encrypted_origin_name can be decrypted using the
Issuer's private key (the private key associated with ISSUER_KEY), and matches
an ORIGIN_NAME that is served by the Issuer
- For version 1, the AccessTokenRequest.blinded_req is of the correct size

If any of these conditions is not met, the Issuer MUST return an HTTP 400 error to the Mediator,
which will forward the error to the client.

If the request is valid, the Issuer then can use the value from "Sec-Token-Count" to determine if
the Client is allowed to receive a token for this Origin during the current policy window. If the
Issuer refuses to issue more tokens, it responds with an HTTP 429 (Too Many Requests) error to the
Mediator, which will forward the error to the client.

The Issuer determines the correct ORIGIN_TOKEN_KEY by using the decrypted ORIGIN_NAME value. Issuers
are expected to be able to deterministically select the correct key based on information sent in
the request. Clients do not indicate the ORIGIN_TOKEN_KEY to use, to prevent Origins from choosing
per-client keys.

### Issuer-to-Mediator Response {#response-one}

If the Issuer is willing to give a token to the Client, the Issuer verifies the token request
using "mapping_generator", "mapping_key", and "mapping_proof":

~~~
valid = SchnorrVerify(mapping_generator, mapping_key, mapping_proof)
~~~

If this fails, the Issuer rejects the request with a 400 error. Otherwise, the Issuer decrypts
AccessTokenRequest.encrypted_origin_name to discover "origin". If this fails, the Issuer
rejects the request with a 400 error. The Issuer then evaluates the mapping over the ORIGIN_SECRET
pertaining to the origin for this issuer:

~~~
mapping_input = DeserializeElement(AccessTokenRequest.mapping_key)
index = ORIGIN_SECRET * mapping_input
mapping_index = SerializeElement(index)
~~~

If DeserializeElement fails, or if AccessTokenRequest.mapping_key is the identity element, the Issuer
rejects the request with a 400 error.

The Issuer completes the issuance flow by computing a blinded response as follows:

~~~
blind_sig = rsabssa_blind_sign(skP, AccessTokenRequest.blinded_req)
~~~

`skP` is the private key corresponding to ORIGIN_TOKEN_KEY, known only to the Issuer.

The Issuer generates an HTTP response with status code 200 whose body consists of
blind_sig, with the content type set as "message/access-token-response" and the
mapping_tag set in the "Sec-Token-Origin" header.

~~~
:status = 200
content-type = message/access-token-response
content-length = 512
sec-token-origin = mapping_index

<Bytes containing the blind_sig>
~~~

### Mediator-to-Client Response {#response-two}

Upon receipt of a successful response from the Issuer, the Mediator extracts the
"Sec-Token-Origin" header, and uses the value to determine ANON_ISSUER_ORIGIN_ID.

~~~
index = DeserializeElement(mapping_index)
nonce = DeserializeScalar(mapping_nonce)
ANON_ISSUER_ORIGIN_ID = (nonce^(-1)) * index
~~~

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
{{scheme}} using the token input message and output sig.

### Encrypting Origin Names {#encrypt-origin}

Given a `KeyConfig` (ISSUER_KEY), Clients produce encrypted_origin_name using the
following values:

- the key identifier from the configuration, keyID, with the corresponding KEM identified by kemID,
the public key from the configuration, pkI, and;
- a selected combination of KDF, identified by kdfID, and AEAD, identified by aeadID.

Beyond the key configuration inputs, Clients also require the blind signature request
(`blinded_req`) and the request tag (`request_tag`). Together, these
are used to encapsulate ORIGIN_NAME (`origin_name`) and produce ENCRYPTED_ORIGIN_NAME
(`encrypted_origin`) as follows:

1. Compute an {{HPKE}} context using pkI, yielding context and encapsulation key enc.
1. Construct associated data, aad, by concatenating the values of keyID, kemID, kdfID,
   aeadID, `blinded_req`, and `request_tag`, as one 8-bit integer, three 16-bit integers,
   the value of `blinded_req`, and the value of `request_tag`, respectively, each in
   network byte order.
1. Encrypt (seal) request with aad as associated data using context, yielding ciphertext ct.
1. Concatenate the values of aad, enc, and ct, yielding an Encapsulated Request enc_request.

Note that enc is of fixed-length, so there is no ambiguity in parsing this structure.

In pseudocode, this procedure is as follows:

~~~
enc, context = SetupBaseS(pkI, "OriginTokenRequest")
aad = concat(encode(1, keyID),
             encode(2, kemID),
             encode(2, kdfID),
             encode(2, aeadID),
             encode(len(mapping_generator), mapping_generator),
             encode(len(mapping_key), mapping_key),
             encode(len(mapping_proof), mapping_proof),
             encode(len(blinded_req), blinded_req),
             encode(32, request_tag))
ct = context.Seal(aad, origin_name)
encrypted_origin_name = concat(aad, enc, ct)
~~~

Issuers reverse this procedure to recover ORIGIN_NAME by computing the AAD as described
above and decrypting encrypted_origin_name with their private key skI, the private key
corresponding to pkI. In pseudocode, this procedure is as follows:

~~~
keyID, kemID, kdfID, aeadID, token_request, request_tag, enc, ct = parse(encrypted_origin_name)
aad = concat(encode(1, keyID),
             encode(2, kemID),
             encode(2, kdfID),
             encode(2, aeadID),
             encode(len(mapping_generator), mapping_generator),
             encode(len(mapping_key), mapping_key),
             encode(len(mapping_proof), mapping_proof),
             encode(len(blinded_req), blinded_req),
             encode(32, request_tag))
enc, context = SetupBaseR(enc, skI, "OriginTokenRequest")
origin_name, error = context.Open(aad, ct)
~~~

### Non-Interactive Schnorr Proof of Knowledge {#nizk-dl}

[[OPEN ISSUE: describe POG dependency and notation somewhere]]

Each Issuance request requires evaluation and verification of a Schnorr proof-of-knowledge.
Given input secret "secret" and two elements, "base" and "target", generation of this
proof (u, c, z), denoted SchnorrProof(secret, base, target), works as follows:

~~~
r = RandomScalar()
u = r * base
c = HashToScalar(SerializeElement(base) || SerializeElement(target) || SerializeElement(mask))
z = r + (c * secret)
~~~

The proof is encoded by serializing (u, c, z) as follows:

~~~
struct {
   uint8_t u[Ne];
   uint8_t c[Ns];
   uint8_t z[Ns];
} Proof;
~~~

Verification of a proof (u, c, z), denoted SchnorrVerify(base, target, proof),
works as follows:

~~~
c = HashToScalar(SerializeElement(base) || SerializeElement(target) || SerializeElement(mask))
expected_left = base * z
expected_right = u + (target * c)
~~~

The proof is considered valid if expected_left == expected_right.

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
can use other per-Client information for the client identifier mapping, such as IP addressess.

## Denial of Service

Requesting and verifying a Private Access Token is more expensive than checking an implicit
signal, such as an IP address, especially since malicious clients can generate garbage
Private Access Tokens and for Origins to work. However, similar DoS vectors already exist
for Origins, e.g., at the underlying TLS layer.

## Channel Security

An attacker that can act as an intermediate between Mediator and Issuer communication can
influence or disrupt the ability for the Issuer to correctly rate-limit token issuance.
All communication channels MUST use server-authenticated HTTPS. Where appropriate, e.g., between
Clients and Mediators, connections MAY mutually authenticate both client and server, or use mechanisms
such as TLS certificate pinning, to mitigate the risk of channel compromise.

An attacker that can intermediate the channel between Client and Origin can
observe a TokenChallenge, and can view a Token being presented for authentication
to an Origin. Scoping the TokenChallenge nonce to the Client HTTP session prevents
Tokens from being collected in one session and then presented to the Origin in another.
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
Clients MUST verify that the origin_name presented in the TokenChallenge structure ({{scheme}})
matches the origin that is providing the HTTP authentication challenge, where the matching logic
is defined for same-origin policies in {{?RFC6454}}. Clients MAY further limit which
authentication challenges they are willing to respond to, for example by only accepting
challenges when the origin is a web site to which the user navigated.

## Client Identification with Unique Keys

Client activity could be linked if an Origin and Issuer collude to have unique keys targeted
at specific Clients or sets of Clients.

To mitigate the risk of a targetted ISSUER_KEY, the Mediator can observe and validate
the key_id presented by the Client to the Issuer. As described in {{issuance}}, Mediators
MUST validate that the key_id in the Client's AccessTokenRequest matches a known public key
for the Issuer. The Mediator needs to support key rotation, but ought to disallow very rapid key
changes, which could indicate that an Origin is colluding with an Issuer to try to rotate the key
for each new Client in order to link the client activity.

To mitigate the risk of a targetted ORIGIN_TOKEN_KEY, the protocol expects that an Issuer has only
a single valid public key for signing tokens at a time. The Client does not present the key_id
of the token public key to the Issuer, but instead expects the Issuer to infer the correct key based
on the information the Issuer knows, specifically the origin_name itself.

## Issuer and Mediator Ownership

Issuers and Mediators should be run by mutually distinct organizations to limit
information sharing. A single entity running an issuer and mediator for a single redemption
can view the origins being accessed by a given client. Running the issuer and mediator in
this 'single issuer/mediator' fashion reduces the privacy promises to those of Privacy Pass.
This may be desirable for a redemption flow that is limited to specific issuers and mediators,
but should be avoided where hiding origins from the mediator is desirable.

# IANA Considerations {#iana}

## Authentication Scheme

This document registers the "PrivateAccessToken" authentication scheme in the "Hypertext
Transfer Protocol (HTTP) Authentication Scheme Registry" established by {{!RFC7235}}.

Authentication Scheme Name: PrivateAccessToken

Pointer to specification text: {{scheme}} of this document


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
corresponding media types types:

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
