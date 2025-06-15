# Common Access Token (CAT)
A Rust implementation of the Common Access Token specification, which is based on CBOR Object Signing and Encryption (COSE).

This repository is based on https://crates.io/crates/common-access-token version 0.2.2

### New features added
- Create token with cose_mac0 or cose_sign1 tag
- option to add CWT tag 
- Fully backward compatible with the crate variant 0.2.2

## Overview
Common Access Tokens are compact, secure tokens designed for efficient transmission in resource-constrained environments. They use CBOR encoding for smaller token sizes compared to JSON-based tokens like JWT.

## Features
- CBOR-encoded tokens for compact representation
- Support for both COSE_Sign1 and COSE_Mac0 structures
- HMAC-SHA256 authentication
- Protected and unprotected headers
- Standard registered claims (issuer, subject, audience, expiration, etc.)
- Custom claims with string, binary, integer, and nested map values
- CAT-specific claims for URI validation (CATU), HTTP method restrictions (CATM), replay protection (CATREPLAY), and token renewal (CATR)
- Comprehensive token verification including CAT-specific claim validation