# Privacy Proxy Specifications

This repository collects various specifications and Internet drafts that will be supported by privacy proxies.

## Privacy Pass Tokens

* [Architecture](https://ietf-wg-privacypass.github.io/base-drafts/draft-ietf-privacypass-architecture.html)

* [Authentication Scheme](https://tfpauly.github.io/privacy-proxy/#go.draft-pauly-privacypass-auth-scheme.html)

* [Basic Issuance](https://ietf-wg-privacypass.github.io/base-drafts/draft-ietf-privacypass-protocol.html)

* [Rate-Limited Token Issuance](https://tfpauly.github.io/privacy-proxy/#go.draft-privacypass-rate-limit-tokens.html)

## Private Access Tokens

(Being replaced by rate-limited token issuance in privacy pass, see above)

* [Editor's Copy](https://tfpauly.github.io/privacy-proxy/#go.draft-private-access-tokens.html)

## The Geohash HTTP Client Hint

* [Editor's Copy](https://tfpauly.github.io/privacy-proxy/#go.draft-pauly-httpbis-geohash-hint.html)

## The Privacy Token HTTP Authentication Scheme

(Being replaced by privacy pass authentication scheme, see above)

* [Editor's Copy](https://tfpauly.github.io/privacy-proxy/#go.draft-privacy-token.html)

## HTTP Header Fields for Proxied SVCB Metadata

* [Editor's Copy](https://tfpauly.github.io/privacy-proxy/#go.draft-proxied-svcb-headers.html)

## Building the Drafts

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

This requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/master/doc/SETUP.md).


## Contributing

See the
[guidelines for contributions](https://github.com/tfpauly/privacy-proxy/blob/main/CONTRIBUTING.md).
