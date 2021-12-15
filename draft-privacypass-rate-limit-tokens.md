---
title: "Rate-Limited Token Issuance Protocol"
abbrev: PP Issuance
docname: draft-ietf-privacypass-rate-limit-tokens-latest
category: info

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

This document specifies a variant of the Privacy Pass issuance protocol
that allows for tokens to be rate-limited on a per-origin basis. This
enables origins to use tokens for use cases that need to restrict access
from anonymous clients.

--- middle

# Introduction

This document specifies a variant of the Privacy Pass issuance protocol
(as defined in {{!ARCH=I-D.ietf-privacypass-architecture}}) that allows
for tokens to be rate-limited on a per-origin basis. This enables origins
to use tokens for use cases that need to restrict access from anonymous clients.

The base Privacy Pass issuance protocol {{!ISSUANCE=I-D.ietf-privacypass-protocol}}
defines stateless anonymous tokens, which can either be publicly verifiable
or not.

This variant build upon the publicly verifiable issuance protocol that uses
RSA Blind Signatures {{!BLINDSIG=I-D.irtf-cfrg-rsa-blind-signatures}}, and
allows tokens to be rate-limited on a per-origins basis. This means that
a client will only be able to receive a limited number of tokens associated
with a given origin server within a fixed period of time.

This issuance protocol registers the Rate-Limited Blind RSA token type
{{iana-token-type}}, to be used with the PrivateToken HTTP authentication
scheme defined in [http-auth-doc].

## Motivation

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

# Terminology {#terms}

{::boilerplate bcp14}

Unless otherwise specified, this document encodes protocol messages in TLS notation
from {{!TLS13=RFC8446}}, Section 3.

This draft includes pseudocode that uses the functions and conventions defined
in {{!HPKE=I-D.irtf-cfrg-hpke}}.

Encoding an integer to a sequence of bytes in network byte order is described
using the function "encode(n, v)", where "n" is the number of bytes and "v" is
the integer value. The function "len()" returns the length of a sequence of bytes.

The following terms are defined in {{ARCH}} and are used throughout this
document:

- Client: An entity that provides authorization tokens to services
  across the Internet, in return for authorization.
- Issuer: An entity that produces Privacy Pass tokens to clients.
- Attester: An entity that can attest to properties about the client,
including previous patterns of access.
- Origin: The server which which the client can redeem tokens.
- Issuance Protocol: The protocol exchange that involves the client,
attester, and issuer, used to generate tokens.

The following terms are defined in [http-auth-doc], which defines the
interactions between clients and origins:

- Issuer Name: The name that identifies the Issuer, which is an entity
that can generate tokens for a Client using one or more issuance protocols.
- Issuer Key: Keying material that can be used with an issuance protocol
to create a signed token.
- Origin Name: The name that identifies the Origin, as included in a
TokenChallenge.

Additionally, this document defines several terms that are unique to the
rate-limited issuance protocol:

- Issuer Policy Window: The period over which an Issuer will track access
policy, defined in terms of seconds and represented as a uint64. The state
that the Attester keeps for a Client is specific to a policy window.
The effective policy window for a specific Client starts when the Client
first sends a request associated with an Issuer.

- Origin Name Key: The public key used to encrypt values such as
Origin Name in requests from Clients to the Issuer, so that Attesters cannot learn
the Origin Name value. Each Origin Name Key is used across all requests on the
Issuer, for different Origins.

- Anonymous Origin ID: An identifier that is generated by the Client and marked
on requests to the Attester, which represents a specific Origin anonymously. The Client
generates a stable Anonymous Origin ID for each Origin Name, to allow the Attester
to count token access without learning the Origin Name.

- Client Key: A public key chosen by the Client and shared only with the Attester.

- Client Secret: The secret key used by the Client during token issuance, whose public key
(Client Key) is shared with the Attester.

- Issuer Origin Secret: A per-origin secret key used by the Issuer during token issuance,
whose public key is not shared with anyone.

- Anonymous Issuer Origin ID: An identifier that is generated by Issuer based on an
Issuer Origin Secret that is per-Client and per-Origin. See {{response-two}} for details
of derivation.

# Configuration {#setup}

Issuers MUST provide three parameters for configuration:

1. Issuer Policy Window: a uint64 of seconds as defined in {{terms}}.
1. Issuer Request URI: a token request URL for generating access tokens.
   For example, an Issuer URL might be https://issuer.example.net/access-token-request. This parameter
   uses resource media type "text/plain".
1. Origin Name Key: a `KeyConfig` as defined in {{!OHTTP=I-D.thomson-http-oblivious}} to use when
   encrypting the Origin Name in issuance requests. This parameter uses resource media type
   "application/ohttp-keys".

These parameters can be obtained from an Issuer via a directory object, which is a JSON
object whose field names and values are raw values and URLs for the parameters.

| Field Name           | Value                                            |
|:---------------------|:-------------------------------------------------|
| issuer-policy-window | Issuer Policy Window as a JSON number            |
| issuer-request-uri   | Issuer Request URI resource URL as a JSON string |
| origin-name-key      | Origin Name Key resource URL as a JSON string    |

As an example, the Issuer's JSON directory could look like:

~~~
 {
    "issuer-token-window": 86400,
    "issuer-request-uri": "https://issuer.example.net/access-token-request"
    "origin-name-key": "https://issuer.example.net/key",
 }
~~~

Issuer directory resources have the media type "application/json"
and are located at the well-known location /.well-known/token-issuer-directory.

# Token Challenge Requirements

TODO

- Must be interactive, include a nonce
- Must be per-origin
- Add the origin name key to the challenge

# Issuance Protocol {#issuance}

This section describes the Issuance protocol for a Client to request and receive
a token from an Issuer. Token issuance involves a Client, Attester, and Issuer,
with the following steps:

1. The Client sends a token request to the Attester, encrypted using an Issuer-specific key

1. The Attester validates the request and proxies the request to the Issuer

1. The Issuer decrypts the request and sends a response back to the Attester

1. The Attester verifies the response and proxies the response to the Client

The Issuance protocol has a number of underlying cryptographic dependencies for
operation:

- RSA Blind Signatures {{BLINDSIG}}, for issuing and constructing Tokens. This support
is the same as used in the base publicly verifiable token issuance protocol {{ISSUANCE}}

- {{HPKE}}, for encrypting the origin server name in transit between Client and Issuer across the Attester.

- Prime Order Groups (POGs), for computing stable mappings between (Client, Origin) pairs. This
  document uses notation described in {{!VOPRF=I-D.irtf-cfrg-voprf, Section 2.1}}, and, in particular,
  the functions RandomScalar(), Generator(), SerializeScalar(), SerializeElement(), and HashToScalar().

- Non-Interactive proof-of-knowledge (POK), as described in {{nizk-dl}}, for verifying correctness of Client requests.

Clients and Issuers are required to implement all of these dependencies, whereas Attesters are required
to implement POG and POK support.

## State Requirements

The Issuance protocol requires each participating endpoint to maintain some
necessary state, as described in this section.

### Client State {#client-state}

A Client is required to have the following information, derived from a given TokenChallenge:

- Origin Name, a hostname referring to the Origin {{!RFC6454}}. This is
  the value of TokenChallenge.origin_name.
- Issuer Key, a blind signature public key corresponding to the Issuer Name
  identified by the TokenChallenge.issuer_name.
- Origin Name Key, a public key used to encrypt requests corresponding to the
  Issuer identified by TokenChallenge.issuer_name.

Clients maintain a stable Client Key that they use for all communication with
a specific Attester. Client Key is a public key, where the corresponding private key
Client Secret is known only to the client.

If the client loses this (Client Key, Client Secret), they may generate a new tuple. The
Attester will enforce if a client is allowed to use this new Client Key. See {{attester-state}}
for details on this enforcement.

Clients also need to be able to generate an Anonymous Origin ID value that corresponds
to the Origin Name, to send in requests to the Attester.

Anonymous Origin ID MUST be a stable and unpredictable 32-byte value computed by the Client.
Clients MUST NOT change this value across token requests for the same Origin Name. Doing
so will result in token issuance failure (specifically, when an Attester rejects a request
upon detecting two Anonymous Origin ID values that map to the same Origin).

One possible mechanism for implementing this identifier is for the Client to store a mapping
between the Origin Name and a randomly generated Anonymous Origin ID for future requests. Alternatively,
the Client can compute a PRF keyed by a per-client secret (Client Secret) over the Origin Name,
e.g., Anonymous Origin ID = HKDF(secret=Client Secret, salt="", info=Origin Name).

### Attester State {#attester-state}

An Attester is required to maintain state for every authenticated Client. The mechanism
of identifying a Client is specific to each Attester, and is not defined in this document.
As examples, the Attester could use device-specific certificates or account authentication
to identify a Client.

Attesters must enforce that Clients don't change their Client Key frequently, to ensure Clients can't
regularily evade the per-client policy as seen by the issuer. Attesters MUST NOT allow Clients to
change their Client Key more than once within a policy window, or in the subsequent policy window
after a previous Client Key change. Alternative schemes where the Attester stores the encrypted
(Client Key, Client Secret) tuple on behalf of the client are possble but not described here.

Attesters are expected to know the Issuer Policy Window for any Issuer Name to which
they allow access. This information can be retrieved using the URIs defined in {{setup}}.

For each Client-Issuer pair, an Attester maintains a policy window
start and end time for each Issuer from which a Client requests a token.

For each tuple of (Client Key, Anonymous Origin ID, policy window), the Attester maintains the
following state:

- A counter of successful tokens issued
- Whether or not a previous request was rejected by the Issuer
- The last received Anonymous Issuer Origin ID value for this Anonymous Origin ID, if any

### Issuer State {#issuer-state}

Issuers maintain a stable Issuer Origin Secret that they use in calculating values returned
to the Attester for each origin. If this value changes, it will open up a possibility
for Clients to request extra tokens for an Origin without being limited, within a
policy window.

Issuers are expected to have the private key that corresponds to Origin Name Key,
which allows them to decrypt the Origin Name values in requests.

Issuers also need to know the set of valid Issuer Key public keys and corresponding
private key, for each Origin Name that is served by the Issuer. Origins SHOULD update
their view of the Issuer Key regularly to ensure that Client requests do not fail
after Issuer Key rotation.

## Issuance HTTP Headers

The Issuance protocol defines four new HTTP headers that are used in requests
and responses between Clients, Attesters, and Issuers (see {{iana-headers}}).

The "Sec-Token-Origin" is an Item Structured Header {{!RFC8941}}. Its
value MUST be a Byte Sequence. This header is sent both on Client-to-Attester
requests ({{request-one}}) and on Issuer-to-Attester responses ({{response-one}}).
Its ABNF is:

~~~
    Sec-Token-Origin = sf-binary
~~~

The "Sec-Token-Client" is an Item Structured Header {{!RFC8941}}. Its
value MUST be a Byte Sequence. This header is sent on Client-to-Attester
requests ({{request-one}}), and contains the bytes of Client Key.
Its ABNF is:

~~~
    Sec-Token-Client = sf-binary
~~~

The "Sec-Token-Nonce" is an Item Structured Header {{!RFC8941}}. Its
value MUST be a Byte Sequence. This header is sent on Client-to-Attester
requests ({{request-one}}), and contains a per-request nonce value.
Its ABNF is:

~~~
    Sec-Token-Nonce = sf-binary
~~~

The "Sec-Token-Count" is an Item Structured Header {{!RFC8941}}. Its
value MUST be an Integer. This header is sent on Attester-to-Issuer
requests ({{request-one}}), and contains the number of times a
Client has previously received a token for an Origin. Its ABNF is:

~~~
    Sec-Token-Count = sf-integer
~~~

## Client-to-Attester Request {#request-one}

The Client and Attester MUST use a secure and Attester-authenticated HTTPS
connection. They MAY use mutual authentication or mechanisms such as TLS
certificate pinning, to mitigate the risk of channel compromise; see
{{sec-considerations}} for additional about this channel.

Issuance begins by Clients hashing the TokenChallenge to produce a token input
as message = SHA256(challenge), and then blinding message as follows:

~~~
blinded_req, blind_inv = rsabssa_blind(Issuer Key, message)
~~~

The Client MUST use a randomized variant of RSABSSA in producing this signature with
a salt length of at least 32 bytes.

The Client uses Client Key and Client Secret to generate proof of its request as
described in {{client-stable-mapping}}, yielding output client_origin_index_blind and
client_origin_index_request. The Client then constructs a TokenRequest
using client_origin_index_request, blinded_req, and origin information.

~~~
struct {
   uint8_t version;
   uint8_t client_origin_index_request[Ne+Ne+Np];
   uint8_t token_key_id;
   uint8_t blinded_req[Nk];
   uint8_t issuer_key_id[32];
   uint8_t encrypted_origin_name<1..2^16-1>;
} TokenRequest;
~~~

The structure fields are defined as follows:

- "version" is a 1-octet integer, which matches the version in the TokenChallenge.
This document defines version 1.

- "client_origin_index_request" is computed as described in {{client-stable-mapping}}.

- "token_key_id" is the least significant byte of the Issuer Key key ID, which is
generated as SHA256(public_key), where public_key is a DER-encoded SubjectPublicKeyInfo
object carrying Issuer Key.

- "blinded_req" is the Nk-octet request defined above.

- "issuer_key_id" is a collision-resistant hash that identifies the Origin Name Key public
key, generated as SHA256(KeyConfig).

- "encrypted_origin_name" is an encrypted structure that contains Origin Name,
calculated as described in {{encrypt-origin}}.

The Client then generates an HTTP POST request to send through the Attester to
the Issuer, with the AccessTokenRequest as the body. The media type for this request
is "message/token-request". The Client includes the "Sec-Token-Origin" header,
whose value is Anonymous Origin ID; the "Sec-Token-Client" header, whose value is Client Key; and
the "Sec-Token-Nonce" header, whose value is client_origin_index_blind. The Client
sends this request to the Attester's proxy URI. An example request is shown below,
where Nk = 512.

~~~
:method = POST
:scheme = https
:authority = issuer.net
:path = /token-request
accept = message/token-response
cache-control = no-cache, no-store
content-type = message/token-request
content-length = 512
sec-token-origin = Anonymous Origin ID
sec-token-client = Client Key
sec-token-nonce = client_origin_index_blind

<Bytes containing the AccessTokenRequest>
~~~

If the Attester detects a version in the AccessTokenRequest that it does not recognize
or support, it MUST reject the request with an HTTP 400 error.

The Attester also checks to validate that the issuer_key_id in the client's AccessTokenRequest
matches a known Origin Name Key public key for the Issuer. For example, the Attester can
fetch this key using the API defined in {{setup}}. This check is done to help ensure that
the Client has not been given a unique key that could allow the Issuer to fingerprint or target
the Client. If the key does not match, the Attester rejects the request with an HTTP
400 error. Note that Attesters need to be careful in cases of key rotation; see
{{privacy-considerations}}.

The Attester finally checks to ensure that the AccessTokenRequest.client_origin_index_request is valid
for the given Client Key; see {{nizk-dl}} for verification details. If the index is invalid,
the Attester rejects the request with an HTTP 400 error.

If the Attester accepts the request, it will look up the state stored for this Client.
It will look up the count of previously generate tokens for this Client using the same
Anonymous Origin ID. See {{attester-state}} for more details.

If the Attester has stored state that a previous request for this Anonymous Origin ID was
rejected by the Issuer in the current policy window, it SHOULD reject the request without
forwarding it to the Issuer.

If the Attester detects this Client has changed their Client Key more frequently than allowed
as described in {{attester-state}}, it SHOULD reject the request without forwarding it to
the Issuer.

## Attester-to-Issuer Request {#request-two}

The Attester and the Issuer MUST use a secure and Issuer-authenticated HTTPS
connection. Also, Issuers MUST authenticate Attesters, either via mutual
TLS or another form of application-layer authentication. They MAY additionally use
mechanisms such as TLS certificate pinning, to mitigate the risk of channel
compromise; see {{sec-considerations}} for additional about this channel.

Before copying and forwarding the Client's AccessTokenRequest request to the Issuer,
the Attester validates the Client's stable mapping request as described in {{attester-stable-mapping}}.
If this fails, the Attester MUST return an HTTP 400 error to the Client. Otherwise, the
Attester then adds a header that includes the count of previous tokens as "Sec-Token-Count".
The Attester MAY also add additional context information, but MUST NOT add information
that will uniquely identify a Client.

~~~
:method = POST
:scheme = https
:authority = issuer.net
:path = /token-request
accept = message/token-response
cache-control = no-cache, no-store
content-type = message/token-request
content-length = 512
sec-token-count = 3

<Bytes containing the AccessTokenRequest>
~~~

Upon receipt of the forwarded request, the Issuer validates the following conditions:

- The "Sec-Token-Count" header is present
- The AccessTokenRequest contains a supported version
- For version 1, the AccessTokenRequest.issuer_key_id corresponds to the ID of the Origin Name Key held by the Issuer
- For version 1, the AccessTokenRequest.encrypted_origin_name can be decrypted using the
Issuer's private key (the private key associated with Origin Name Key), and matches
an Origin Name that is served by the Issuer
- For version 1, the AccessTokenRequest.blinded_req is of the correct size
- For version 1, the AccessTokenRequest.token_key_id corresponds to an ID of an Issuer Key
for the corresponding Origin Name

If any of these conditions is not met, the Issuer MUST return an HTTP 400 error to the Attester,
which will forward the error to the client.

If the request is valid, the Issuer then can use the value from "Sec-Token-Count" to determine if
the Client is allowed to receive a token for this Origin during the current policy window. If the
Issuer refuses to issue more tokens, it responds with an HTTP 429 (Too Many Requests) error to the
Attester, which will forward the error to the client.

The Issuer determines the correct Issuer Key by using the decrypted Origin Name value and
AccessTokenRequest.token_key_id. If there is no Issuer Key whose truncated key ID matches
AccessTokenRequest.token_key_id, the Issuer MUST return an HTTP 401 error to Attester, which will
forward the error to the client. The Attester learns that the client's view of the Origin key
was invalid in the process.

## Issuer-to-Attester Response {#response-one}

If the Issuer is willing to give a token to the Client, the Issuer decrypts
AccessTokenRequest.encrypted_origin_name to discover "origin". If this fails, the Issuer rejects
the request with a 400 error. Otherwise, the Issuer validates and processes the token request
with Issuer Origin Secret corresponding to the designated Origin as described in {{issuer-stable-mapping}}.
If this fails, the Issuer rejects the request with a 400 error. Otherwise, the output is
client_origin_index_result.

The Issuer completes the issuance flow by computing a blinded response as follows:

~~~
blind_sig = rsabssa_blind_sign(skP, AccessTokenRequest.blinded_req)
~~~

`skP` is the private key corresponding to Issuer Key, known only to the Issuer.

The Issuer generates an HTTP response with status code 200 whose body consists of
blind_sig, with the content type set as "message/token-response" and the
client_origin_index_result set in the "Sec-Token-Origin" header.

~~~
:status = 200
content-type = message/token-response
content-length = 512
sec-token-origin = client_origin_index_result

<Bytes containing the blind_sig>
~~~

## Attester-to-Client Response {#response-two}

Upon receipt of a successful response from the Issuer, the Attester extracts the
"Sec-Token-Origin" header, and uses the value to determine Anonymous Issuer Origin ID
as described in {{attester-stable-mapping}}.

If the "Sec-Token-Origin" is missing, or if the same Anonymous Issuer Origin ID was previously
received in a response for a different Anonymous Origin ID within the same policy window,
the Attester MUST drop the token and respond to the client with an HTTP 400 status.
If there is not an error, the Anonymous Issuer Origin ID is stored alongside the state
for the Anonymous Origin ID.

For all other cases, the Attester forwards all HTTP responses unmodified to the Client
as the response to the original request for this issuance.

When the Attester detects successful token issuance, it MUST increment the counter
in its state for the number of tokens issued to the Client for the Anonymous Origin ID.

Upon receipt, the Client handles the response and, if successful, processes the
body as follows:

~~~
sig = rsabssa_finalize(Issuer Key, nonce, blind_sig, blind_inv)
~~~

If this succeeds, the Client then constructs a token as described in
[http-auth-doc] using the token input message and output sig.

# Encrypting Origin Names {#encrypt-origin}

Given a `KeyConfig` (Origin Name Key), Clients produce encrypted_origin_name and authenticate
all other contents of the AccessTokenRequest using the following values:

- the key identifier from the configuration, keyID, with the corresponding KEM identified by kemID,
the public key from the configuration, pkI, and;
- a selected combination of KDF, identified by kdfID, and AEAD, identified by aeadID.

Beyond the key configuration inputs, Clients also require the AccessTokenRequest inputs.
Together, these are used to encapsulate Origin Name (`origin_name`) and produce
ENCRYPTED_Origin Name (`encrypted_origin`) as follows:

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
             encode(Ne+Ne+Np, client_origin_index_request),
             encode(1, token_key_id),
             encode(Nk, blinded_req),
             encode(32, issuer_key_id))
ct = context.Seal(aad, origin_name)
encrypted_origin_name = concat(enc, ct)
~~~

Issuers reverse this procedure to recover Origin Name by computing the AAD as described
above and decrypting encrypted_origin_name with their private key skI, the private key
corresponding to pkI. In pseudocode, this procedure is as follows:

~~~
enc, ct = parse(encrypted_origin_name)
aad = concat(encode(1, keyID),
             encode(2, kemID),
             encode(2, kdfID),
             encode(2, aeadID),
             encode(1, version),
             encode(Ne+Ne+Np, client_origin_index_request),
             encode(1, token_key_id),
             encode(Nk, blinded_req),
             encode(32, issuer_key_id))
enc, context = SetupBaseR(enc, skI, "AccessTokenRequest")
origin_name, error = context.Open(aad, ct)
~~~

# Stable Mapping Computation {#stable-mapping}

This section describes the Client, Attester, and Issuer behavior in computing
the stable mapping based on client identity and origin name. At a high level,
this functionality computes y = F(x, k), where x is a per-Client secret and
k is a per-Origin secret, subject to the following constraints:

- The Attester only learns y if the Client in possession of x engages with the protocol;
- The Attester prevents a Client with private input x from running the protocol for input x' that is not equal to x;
- The Issuer does not learn x, nor does it learn when two requests correspond to the same private value x; and
- Neither the Client nor Attester learn k.

The interaction between Client, Attester, and Issuer in computing this
functionality is shown below.

~~~
Client               Attester                Issuer
      (request, proof)
  ---------------------->
                             (request, proof)
                         ---------------------->
                                (response)
                         <----------------------
~~~

The protocol for computing this functionality is divided into sections for
each of the participants. {{client-stable-mapping}} describes Client behavior
for initiating the computation with its per-Client secret, {{attester-stable-mapping}}
describes Attester behavior for verifying Client requests, {{issuer-stable-mapping}}
describes Issuer behavior for computing the mapping with its per-Origin secret,
and {{attester-output-stable-mapping}} describes the final Attester step for
computing the mapping output.

## Client Behavior {#client-stable-mapping}

Given a client secret (Client Secret) and the corresponding key (Client Key),
Clients produce client_origin_index using a Prime Order Groups (POGs) as
described in {{!VOPRF=I-D.irtf-cfrg-voprf, Section 2.1}}. In particular,
the functions RandomScalar(), Generator(), SerializeScalar(), SerializeElement(),
and HashToScalar() are used in the following way.

1. Generate a random scalar blind and multiply Client Key and the group
   generator by this blind, yielding a blinded key and blinded generator.
1. Compute a Schnorr proof-of-knowledge demonstrating knowledge of the
   discrete log of the blinded key with respect to the blinded generator.
1. Serialize the blinded key, blinded generator, and proof, yielding
   client_origin_index_key, client_origin_index_base, and client_origin_index_proof,
   and concatenate each, yielding client_origin_index_request.
1. Serialize the blind, yielding client_origin_index_blind.
1. Output client_origin_index_blind, client_origin_index_request.

In pseudocode, this is as follows:

~~~
// Generate blind, blinded key, blinded generator, and the proof
blind = RandomScalar()
blind_key = blind * Client Key
blind_generator = blind * Generator()
blind_proof = SchnorrProof(Client Secret, blind_generator, blind_key)

// Serialize and produce outputs
client_origin_index_proof = SerializeProof(blind_proof)
client_origin_index_key = SerializeElement(blind_key)
client_origin_index_base = SerializeElement(blind_generator)
client_origin_index_request = concat(client_origin_index_key,
    client_origin_index_base, client_origin_index_proof)
client_origin_index_blind = SerializeScalar(blind)
~~~

## Attester Behavior (Client Request Validation) {#attester-stable-mapping}

Given a client key (Client Key), client_origin_index_blind, and client_origin_index_request,
Attesters verify the proof for correctness as follows:

1. Deserialize client_origin_index_blind, yielding blind. If this fails, abort.
1. Parse client_origin_index_request as client_origin_index_key, client_origin_index_base, and
   client_origin_index_proof, and deserialize each to yield the blinded key, blinded generator,
   and blind proof.
1. Multiply Client Key and the group generator by blind, yielding a blinded key and
   blinded generator. If these do not match the deserialized blinded key and generator,
   abort.
1. Verify the blind proof against the blinded key and generator. If proof verification
   fails, abort.

In pseudocode, this is as follows:

~~~
blind = DeserializeScalar(client_origin_index_blind)

// Verify the proof parameters against the client's public key
client_origin_index_key, client_origin_index_base, client_origin_index_proof =
    parse(client_origin_index_request)
expected_blind_key = DeserializeElement(client_origin_index_key)
expected_blind_generator = DeserializeElement(client_origin_index_base)
blind_key = blind * Client Key
blind_generator = blind * Generator()
if expected_blind_key != blind_key:
    raise InvalidParameterError
if expected_blind_generator != blind_generator:
    raise InvalidParameterError

// Verify the proof
proof = DeserializeProof(client_origin_index_proof)
valid = SchnorrVerify(blind_generator, blind_key, proof)
if not valid:
   raise InvalidProofError
~~~

## Issuer Behavior {#issuer-stable-mapping}

Given a Client request client_origin_index_request and Issuer Origin Secret, Issuers
verify the request and compute a response as follows:

1. Parse client_origin_index_request as client_origin_index_key, client_origin_index_base, and
   client_origin_index_proof, and deserialize each to yield the blinded key, blinded generator,
   and proof.
1. Verify client_origin_index_proof against the blinded key and generator. If proof verification
   fails, abort.
1. Multiply the blinded key by Issuer Origin Secret, yielding a blinded client key.
1. Serialize the blinded client key, yielding client_origin_index_result.
1. Output client_origin_index_result.

In pseudocode, this is as follows:

~~~
// Verify the proof
client_origin_index_key, client_origin_index_base, client_origin_index_proof =
    parse(client_origin_index_request)
blind_key = DeserializeElement(client_origin_index_key)
blind_generator = DeserializeElement(client_origin_index_base)
proof = DeserializeProof(client_origin_index_proof)
valid = SchnorrVerify(blind_generator, blind_key, proof)
if not valid:
   raise InvalidProofError

// Evaluate the request with the per-Origin secret
evaluated_key = Issuer Origin Secret * blind_key
client_origin_index_result = SerializeElement(evaluated_key)
~~~

## Attester Behavior (Mapping Output Computation) {#attester-output-stable-mapping}

Given an Issuer response client_origin_index_result, Client blind, and Client public
key (Client Key), Attesters complete the mapping computation as follows:

1. Deserialize client_origin_index_result, yielding the evaluated client key.
   If this fails, abort.
1. Multiply the evaluated client key by the multiplicative inverse of the
   Client blind, yielding the mapping result.
1. Run HKDF with the mapping result as the secret, Client Key as the salt, and
   ASCII string "PrivateAccessTokens" as the info string, yielding Anonymous Issuer Origin ID.
1. Output Anonymous Issuer Origin ID.

In pseudocode, this is as follows:

~~~
evaluated_key = DeserialiesElement(client_origin_index_result)
mapping_result = blind^(-1) * evaluated_key
encoded_mapping_result = SerializeElement(mapping_result)
encoded_client_key = SerializeElement(Client Key)
Anonymous Issuer Origin ID = HKDF(secret=encoded_mapping_result,
                             salt=encoded_client_key,
                             info="PrivateAccessTokens")
~~~

# Non-Interactive Schnorr Proof of Knowledge {#nizk-dl}

Each Issuance request requires evaluation and verification of a Schnorr proof-of-knowledge.
Given input secret "secret" and two elements, "base" and "target", this proof demonstrates
knowledge of the discrete log of "target" with respect to "base". Computation of this proof,
denoted SchnorrProof(secret, base, target), works as follows:

~~~
r = RandomScalar()
u = r * base
c = HashToScalar(SerializeElement(base) ||
                 SerializeElement(target) ||
                 SerializeElement(u),
                 dst = "PrivateAccessTokensProof")
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

The size of this structure is Np = Ne + 2*Ns bytes.

Verification of a proof (u, c, z), denoted SchnorrVerify(base, target, proof),
works as follows:

~~~
c = HashToScalar(SerializeElement(base) ||
                 SerializeElement(target) ||
                 SerializeElement(u),
                 dst = "PrivateAccessTokensProof")
expected_left = base * z
expected_right = u + (target * c)
~~~

The proof is considered valid if expected_left is the same as expected_right.

# Security considerations {#sec-considerations}

An attacker that can act as an intermediate between Attester and Issuer
communication can influence or disrupt the ability for the Issuer to correctly
rate-limit token issuance.  All communication channels use server-authenticated
HTTPS. Some connections, e.g., between an Attester and an Issuer, require
mutual authentication between both endpoints. Where appropriate, endpoints
MAY use further enhancements such as TLS certificate pinning to mitigate
the risk of channel compromise.

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

Rate-limited tokens are defined in terms of a Client authenticating to an Origin, where
the "origin" is used as defined in {{?RFC6454}}. In order to limit cross-origin correlation,
Clients MUST verify that the origin_name presented in the TokenChallenge structure ({{challenge}})
matches the origin that is providing the HTTP authentication challenge, where the matching logic
is defined for same-origin policies in {{?RFC6454}}. Clients MAY further limit which
authentication challenges they are willing to respond to, for example by only accepting
challenges when the origin is a web site to which the user navigated.

## Client Identification with Unique Keys

Client activity could be linked if an Origin and Issuer collude to have unique keys targeted
at specific Clients or sets of Clients.

To mitigate the risk of a targeted Origin Name Key, the Attester can observe and validate
the issuer_key_id presented by the Client to the Issuer. As described in {{issuance}}, Attesters
MUST validate that the issuer_key_id in the Client's AccessTokenRequest matches a known public key
for the Issuer. The Attester needs to support key rotation, but ought to disallow very rapid key
changes, which could indicate that an Origin is colluding with an Issuer to try to rotate the key
for each new Client in order to link the client activity.

## Collusion Among Different Entities {#collusion}

Collusion among the different entities in the Privacy Pass architecture can result in
exposure of a client's per-origin access patterns.

For this issuance protocol, Issuers and Attesters should be run by mutually distinct
organizations to limit information sharing. A single entity running an Issuer and Attester
for a single token issuance flow can view the origins being accessed by a given client.
Running the Issuer and Attester in this 'single Issuer/Attester' fashion reduces the privacy
promises of no one entity being able to learn Client browsing patterns. This may be desirable
for a redemption flow that is limited to specific Issuers and Attesters, but should be avoided
where hiding origin names from the Attester is desirable.

If a Attester and Origin are able to collude, they can correlate a client's identity
and origin access patterns through timestamp correlation. The timing of a request to an
Origin and subsequent token issuance to a Attester can reveal the Client
identity (as known to the Attester) to the Origin, especially if repeated over multiple accesses.

# Deployment Considerations {#deploy}

## Origin Key Rollout

Issuers SHOULD generate a new (Issuer Key, Issuer Origin Secret) regularly, and
SHOULD maintain old and new secrets to allow for graceful updates. The RECOMMENDED
rotation interval is two times the length of the policy window for that
information. During generation, issuers must ensure the `token_key_id` (the 8-bit
prefix of SHA256(Issuer Key)) is different from all other `token_key_id`
values for that origin currently in rotation. One way to ensure this uniqueness
is via rejection sampling, where a new key is generated until its `token_key_id` is
unique among all currently in rotation for the origin.

# IANA considerations

## Token Type {#iana-token-type}

This document updates the "Token Type" Registry [http-auth-doc] with the following value:

| Value  | Name                   | Public | Public Metadata | Private Metadata | Nk  | Reference        |
|:-------|:-----------------------|:-------|:----------------|:-----------------|:----|:-----------------|
| 0x0003 | Rate-Limited Blind RSA | Y      | N               | N                | 512 | This document    |
{: #aeadid-values title="Token Types"}

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
