# json-proof-token

![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
[![](https://img.shields.io/crates/v/json-proof-token?style=flat-square)](https://crates.io/crates/json-proof-token)
[![](https://img.shields.io/docsrs/json-proof-token?style=flat-square)](https://docs.rs/json-proof-token/)


## Decoder

[Here](https://cybersecurity-links.github.io/json-proof-token/) you can find a simple decoder for JSON Proof Tokens.

## Description

Rust library implementing the new [JOSE Working Group](https://datatracker.ietf.org/wg/jose/documents/) drafts:
- [JSON Web Proof](https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-proof)
- [JSON Proof Algorithms](https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-proof-algorithms) 
- [JSON Proof Token](https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-proof-token)

The specification work for this can be found [here](https://github.com/json-web-proofs/json-web-proofs).

## Supported Features

### JSON Web Keys (JWK)

JWK is defined in [RFC 7517](https://tools.ietf.org/html/rfc7517).

> **NOTE**: To represent **BLS** keys this implementation refers to [draft-ietf-cose-bls-key-representations-05](https://datatracker.ietf.org/doc/html/draft-ietf-cose-bls-key-representations-05).

JWKs are currently used in the proof generation and verification of JWPs.

The tables below represent which `kty` and `crv` are supported at momement.

#### JWK Key Type

| Key Type | Support |
|:--------:|:-------:|
|   `OKP`  |    ✔    |
|   `EC`   |    ✔    |
|   `RSA`  |    ✘    |
|   `oct`  |    ✘    |


#### JWK Elliptic Curve
The standard list of Elliptic Curves can be found [here](https://www.iana.org/assignments/jose/jose.xhtml#web-key-elliptic-curve):

|  Curve Name | Support |
|:---------:|:-------:|
| `P-256` |    ✘    |
|  `P-384`  |    ✘    |
|  `P-521` |    ✘    |
|   `secp256k1`  |    ✘    |
| `Ed25519` |    ✘    |
|  `Ed448`  |    ✘    |
|  `X25519` |    ✘    |
|   `X448`  |    ✘    |


This list is made from the currenlty active draft [Barreto-Lynn-Scott Elliptic Curve Key Representations for JOSE and COSE - v05](https://datatracker.ietf.org/doc/html/draft-ietf-cose-bls-key-representations-05#section-2.2.3).

|  Curve Name | Support |
|:---------:|:-------:|
|  `BLS12381G2` |    ✔    |
|  `BLS12381G1` |    ✘    |
|  `BLS48581G2` |    ✘    |
|  `BLS48581G2` |    ✘    |

### JSON Web Proof Algorithms

The supported algorithm are defined in in the [JPA](https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-proof-algorithms) specification.

> NOTE: Keep in mind that these specifications are in the early stages, and there is a high likelihood that they will undergo significant changes in the future.

#### Single Use
| Algorithm | Support | Remarks |
|:---------:|:-------:|:-------:|
|   `SU-ES256`   |    ✘    |   Named [here](https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-proof-algorithms#section-6.1.10)       |



#### BBS

These `alg` values are temporary and await an update to the official draft that will define names to support both ciphersuites specified in [BBS+](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-04#name-bls12-381-ciphersuites).:
- BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_
- BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_

| Algorithm | Support | Remarks |
|:---------:|:-------:|:-------:|
|    `BLS12381-SHA256`    |    ✔    |         |
|    `BLS12381-SHAKE256`    |    ✔    |         |
|    `BLS12381-SHA256-PROOF`    |    ✔    |         |
|    `BLS12381-SHAKE256-PROOF`    |    ✔    |         |

#### MAC

These are defined [here](https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-proof-algorithms#section-6.3.9):

| Algorithm | Support | Remarks |
|:---------:|:-------:|:-------:|
|    `MAC-H256`    |    ✘    |         |
|    `MAC-H384`    |    ✘    |         |
|    `MAC-H512`    |    ✘    |         |
|    `MAC-K25519`    |    ✘    |         |
|    `MAC-K448`    |    ✘    |         |
|    `MAC-H256K`    |    ✘    |         |


### JSON Web Proof Serialization

| Format         | Support |
|:----------------:|:---------:|
| Compact        |  ✔    |
| JSON   |  ✘    |










## Getting Started


### Requirements

- [Rust](https://www.rust-lang.org/) (>= 1.65)
- [Cargo](https://doc.rust-lang.org/cargo/) (>= 1.65)


### Usage

Add this to your Cargo.toml:

```
[dependencies]
json-proof-token = "0.3.4"
```

### Example
Take a look at the [examples](https://github.com/Cybersecurity-LINKS/json-proof-token/tree/main/examples).

## Tests

TBD