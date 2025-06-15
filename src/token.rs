//! Token implementation for Common Access Token

use crate::claims::{Claims, RegisteredClaims};
use crate::constants::{cose_labels, cwt_keys};
use crate::error::Error;
use crate::header::{Algorithm, CborValue, Header, HeaderMap, KeyId};
use crate::utils::{compute_hmac_sha256, current_timestamp, verify_hmac_sha256};
use minicbor::{Decoder, Encoder};
use std::collections::BTreeMap;

/// Common Access Token structure
#[derive(Debug, Clone)]
pub struct Token {
    /// Token header
    pub header: Header,
    /// Token claims
    pub claims: Claims,
    /// Token signature
    pub signature: Vec<u8>,
    mac_type: Option<MacType>,
    cwt: bool,
}

impl Token {
    /// Create a new token with the given header, claims, and signature
    pub fn new(header: Header, claims: Claims, signature: Vec<u8>) -> Self {
        Self {
            header,
            claims,
            signature,
            mac_type: None,
            cwt: false,
        }
    }

    /// Encode the token to CBOR bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        // COSE_Sign1 = [
        //   protected : bstr .cbor header_map,
        //   unprotected : header_map,
        //   payload : bstr .cbor claims,
        //   signature : bstr
        // ]

        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        if self.cwt {
            enc.tag(minicbor::data::Tag::new(cwt_keys::CWT))?;
        }

        if let Some(mac_type) = &self.mac_type {
            match mac_type {
                MacType::MAC0(true) => {
                    enc.tag(minicbor::data::Tag::new(cose_labels::MAC0))?;
                }
                MacType::SIGN1(true) => {
                    enc.tag(minicbor::data::Tag::new(cose_labels::SIGN1))?;
                }
                _ => {}
            };
        }

        // Start array with 4 items
        enc.array(4)?;

        // 1. Protected header (encoded as CBOR and then as bstr)
        let protected_bytes = encode_map(&self.header.protected)?;
        enc.bytes(&protected_bytes)?;

        // 2. Unprotected header
        encode_map_direct(&self.header.unprotected, &mut enc)?;

        // 3. Payload (encoded as CBOR and then as bstr)
        let claims_map = self.claims.to_map();
        let claims_bytes = encode_map(&claims_map)?;
        enc.bytes(&claims_bytes)?;

        // 4. Signature
        enc.bytes(&self.signature)?;

        Ok(buf)
    }

    /// Decode a token from CBOR bytes
    ///
    /// This function supports both COSE_Sign1 (tag 18) and COSE_Mac0 (tag 17) structures,
    /// as well as custom tags. It will automatically skip any tags and process the underlying
    /// CBOR array.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut dec = Decoder::new(bytes);

        let mut cwt_tag: bool = false;
        let mut mac_tag: Option<MacType> = None;

        // Check if the token starts with a tag (COSE_Sign1 tag = 18, COSE_Mac0 tag = 17, or custom tag = 61)
        if dec.datatype()? == minicbor::data::Type::Tag {
            let tag_result = dec.tag();
            match tag_result {
                Ok(_) => cwt_tag = true,
                _ => {}
            }

            // Check for a second tag
            if dec.datatype()? == minicbor::data::Type::Tag {
                let tag_result = dec.tag();
                match tag_result {
                    Ok(val) => match val.as_u64() {
                        cose_labels::MAC0 => mac_tag = Some(MacType::MAC0(true)),
                        cose_labels::SIGN1 => mac_tag = Some(MacType::SIGN1(true)),
                        _ => {}
                    },
                    _ => {}
                }
            }
        }

        // Expect array with 4 items
        let array_len = dec.array()?.unwrap_or(0);
        if array_len != 4 {
            return Err(Error::InvalidFormat(format!(
                "Expected array of length 4, got {}",
                array_len
            )));
        }

        // 1. Protected header
        let protected_bytes = dec.bytes()?;
        let protected = decode_map(protected_bytes)?;

        // 2. Unprotected header
        let unprotected = decode_map_direct(&mut dec)?;

        // Create header
        let header = Header {
            protected,
            unprotected,
        };

        // 3. Payload
        let claims_bytes = dec.bytes()?;
        let claims_map = decode_map(claims_bytes)?;
        let claims = Claims::from_map(&claims_map);

        // 4. Signature
        let signature = dec.bytes()?.to_vec();

        Ok(Self {
            header,
            claims,
            signature,
            cwt: cwt_tag,
            mac_type: mac_tag,
        })
    }

    /// Verify the token signature
    ///
    /// This function supports both COSE_Sign1 and COSE_Mac0 structures.
    /// It will first try to verify the signature using the COSE_Sign1 structure,
    /// and if that fails, it will try the COSE_Mac0 structure.
    pub fn verify(&self, key: &[u8]) -> Result<(), Error> {
        let alg = self.header.algorithm().ok_or_else(|| {
            Error::InvalidFormat("Missing algorithm in protected header".to_string())
        })?;

        match alg {
            Algorithm::HmacSha256 => {
                // Try with COSE_Sign1 structure first
                let sign1_input = self.sign1_input()?;
                let sign1_result = verify_hmac_sha256(key, &sign1_input, &self.signature);

                if sign1_result.is_ok() {
                    return Ok(());
                }

                // If COSE_Sign1 verification fails, try COSE_Mac0 structure
                let mac0_input = self.mac0_input()?;
                verify_hmac_sha256(key, &mac0_input, &self.signature)
            }
        }
    }

    /// Verify the token claims
    pub fn verify_claims(&self, options: &VerificationOptions) -> Result<(), Error> {
        let now = current_timestamp();

        // Check expiration
        if options.verify_exp {
            if let Some(exp) = self.claims.registered.exp {
                if now >= exp {
                    return Err(Error::Expired);
                }
            } else if options.require_exp {
                return Err(Error::MissingClaim("exp".to_string()));
            }
        }

        // Check not before
        if options.verify_nbf {
            if let Some(nbf) = self.claims.registered.nbf {
                if now < nbf {
                    return Err(Error::NotYetValid);
                }
            }
        }

        // Check issuer
        if let Some(expected_iss) = &options.expected_issuer {
            if let Some(iss) = &self.claims.registered.iss {
                if iss != expected_iss {
                    return Err(Error::InvalidIssuer);
                }
            } else if options.require_iss {
                return Err(Error::MissingClaim("iss".to_string()));
            }
        }

        // Check audience
        if let Some(expected_aud) = &options.expected_audience {
            if let Some(aud) = &self.claims.registered.aud {
                if aud != expected_aud {
                    return Err(Error::InvalidAudience);
                }
            } else if options.require_aud {
                return Err(Error::MissingClaim("aud".to_string()));
            }
        }

        // Check CAT-specific claims
        if options.verify_catu {
            self.verify_catu_claim(options)?;
        }

        if options.verify_catm {
            self.verify_catm_claim(options)?;
        }

        if options.verify_catreplay {
            self.verify_catreplay_claim(options)?;
        }

        Ok(())
    }

    /// Verify the CATU (URI) claim against the provided URI
    fn verify_catu_claim(&self, options: &VerificationOptions) -> Result<(), Error> {
        use crate::constants::{cat_keys, uri_components};
        use url::Url;

        // Get the URI to verify against
        let uri = match &options.uri {
            Some(uri) => uri,
            None => {
                return Err(Error::InvalidClaimValue(
                    "No URI provided for CATU verification".to_string(),
                ))
            }
        };

        // Parse the URI
        let parsed_uri = match Url::parse(uri) {
            Ok(url) => url,
            Err(_) => {
                return Err(Error::InvalidClaimValue(format!(
                    "Invalid URI format: {}",
                    uri
                )))
            }
        };

        // Check if token has CATU claim
        let catu_claim = match self.claims.custom.get(&cat_keys::CATU) {
            Some(claim) => claim,
            None => return Ok(()), // No CATU claim, so nothing to verify
        };

        // CATU claim should be a map
        let component_map = match catu_claim {
            CborValue::Map(map) => map,
            _ => {
                return Err(Error::InvalidUriClaim(
                    "CATU claim is not a map".to_string(),
                ))
            }
        };

        // Verify each component in the CATU claim
        for (component_key, component_value) in component_map {
            match *component_key {
                uri_components::SCHEME => {
                    self.verify_uri_component(
                        &parsed_uri.scheme().to_string(),
                        component_value,
                        "scheme",
                    )?;
                }
                uri_components::HOST => {
                    self.verify_uri_component(
                        &parsed_uri.host_str().unwrap_or("").to_string(),
                        component_value,
                        "host",
                    )?;
                }
                uri_components::PORT => {
                    let port = parsed_uri.port().map(|p| p.to_string()).unwrap_or_default();
                    self.verify_uri_component(&port, component_value, "port")?;
                }
                uri_components::PATH => {
                    self.verify_uri_component(
                        &parsed_uri.path().to_string(),
                        component_value,
                        "path",
                    )?;
                }
                uri_components::QUERY => {
                    let query = parsed_uri.query().unwrap_or("").to_string();
                    self.verify_uri_component(&query, component_value, "query")?;
                }
                uri_components::EXTENSION => {
                    // Extract file extension from path
                    let path = parsed_uri.path();
                    let extension = path.split('.').next_back().unwrap_or("").to_string();
                    if !path.contains('.') || path.ends_with('.') {
                        // No extension or ends with dot
                        self.verify_uri_component(&"".to_string(), component_value, "extension")?;
                    } else {
                        self.verify_uri_component(
                            &format!(".{}", extension),
                            component_value,
                            "extension",
                        )?;
                    }
                }
                _ => {
                    // Ignore unsupported components
                }
            }
        }

        Ok(())
    }

    /// Verify a URI component against match conditions
    fn verify_uri_component(
        &self,
        component: &String,
        match_conditions: &CborValue,
        component_name: &str,
    ) -> Result<(), Error> {
        use crate::constants::match_types;
        use regex::Regex;
        use sha2::{Digest, Sha256, Sha512};

        // Match conditions should be a map
        let match_map = match match_conditions {
            CborValue::Map(map) => map,
            _ => {
                return Err(Error::InvalidUriClaim(format!(
                    "Match conditions for {} is not a map",
                    component_name
                )))
            }
        };

        for (match_type, match_value) in match_map {
            match *match_type {
                match_types::EXACT => {
                    if let CborValue::Text(text) = match_value {
                        if component != text {
                            return Err(Error::InvalidUriClaim(format!(
                                "URI component {} '{}' does not exactly match required value '{}'",
                                component_name, component, text
                            )));
                        }
                    }
                }
                match_types::PREFIX => {
                    if let CborValue::Text(prefix) = match_value {
                        if !component.starts_with(prefix) {
                            return Err(Error::InvalidUriClaim(format!(
                                "URI component {} '{}' does not start with required prefix '{}'",
                                component_name, component, prefix
                            )));
                        }
                    }
                }
                match_types::SUFFIX => {
                    if let CborValue::Text(suffix) = match_value {
                        if !component.ends_with(suffix) {
                            return Err(Error::InvalidUriClaim(format!(
                                "URI component {} '{}' does not end with required suffix '{}'",
                                component_name, component, suffix
                            )));
                        }
                    }
                }
                match_types::CONTAINS => {
                    if let CborValue::Text(contained) = match_value {
                        if !component.contains(contained) {
                            return Err(Error::InvalidUriClaim(format!(
                                "URI component {} '{}' does not contain required text '{}'",
                                component_name, component, contained
                            )));
                        }
                    }
                }
                match_types::REGEX => {
                    if let CborValue::Array(array) = match_value {
                        if let Some(CborValue::Text(pattern)) = array.first() {
                            match Regex::new(pattern) {
                                Ok(regex) => {
                                    if !regex.is_match(component) {
                                        return Err(Error::InvalidUriClaim(format!(
                                            "URI component {} '{}' does not match required regex pattern '{}'", 
                                            component_name, component, pattern
                                        )));
                                    }
                                }
                                Err(_) => {
                                    return Err(Error::InvalidUriClaim(format!(
                                        "Invalid regex pattern: {}",
                                        pattern
                                    )))
                                }
                            }
                        }
                    }
                }
                match_types::SHA256 => {
                    if let CborValue::Bytes(expected_hash) = match_value {
                        let mut hasher = Sha256::new();
                        hasher.update(component.as_bytes());
                        let hash = hasher.finalize();

                        if hash.as_slice() != expected_hash.as_slice() {
                            return Err(Error::InvalidUriClaim(format!(
                                "URI component {} '{}' SHA-256 hash does not match expected value",
                                component_name, component
                            )));
                        }
                    }
                }
                match_types::SHA512_256 => {
                    if let CborValue::Bytes(expected_hash) = match_value {
                        let mut hasher = Sha512::new();
                        hasher.update(component.as_bytes());
                        let hash = hasher.finalize();
                        let truncated_hash = &hash[0..32]; // Take first 256 bits (32 bytes)

                        if truncated_hash != expected_hash.as_slice() {
                            return Err(Error::InvalidUriClaim(format!(
                                "URI component {} '{}' SHA-512/256 hash does not match expected value", 
                                component_name, component
                            )));
                        }
                    }
                }
                _ => {
                    // Ignore unsupported match types
                }
            }
        }

        Ok(())
    }

    /// Verify the CATM (HTTP method) claim against the provided method
    fn verify_catm_claim(&self, options: &VerificationOptions) -> Result<(), Error> {
        use crate::constants::cat_keys;

        // Get the HTTP method to verify against
        let method = match &options.http_method {
            Some(method) => method,
            None => {
                return Err(Error::InvalidClaimValue(
                    "No HTTP method provided for CATM verification".to_string(),
                ))
            }
        };

        // Check if token has CATM claim
        let catm_claim = match self.claims.custom.get(&cat_keys::CATM) {
            Some(claim) => claim,
            None => return Ok(()), // No CATM claim, so nothing to verify
        };

        // CATM claim should be an array of allowed methods
        let allowed_methods = match catm_claim {
            CborValue::Array(methods) => methods,
            _ => {
                return Err(Error::InvalidMethodClaim(
                    "CATM claim is not an array".to_string(),
                ))
            }
        };

        // Check if the provided method is in the allowed methods list
        let method_upper = method.to_uppercase();
        let method_allowed = allowed_methods.iter().any(|m| {
            if let CborValue::Text(allowed) = m {
                allowed.to_uppercase() == method_upper
            } else {
                false
            }
        });

        if !method_allowed {
            return Err(Error::InvalidMethodClaim(format!(
                "HTTP method '{}' is not allowed. Permitted methods: {:?}",
                method,
                allowed_methods
                    .iter()
                    .filter_map(|m| if let CborValue::Text(t) = m {
                        Some(t.as_str())
                    } else {
                        None
                    })
                    .collect::<Vec<&str>>()
            )));
        }

        Ok(())
    }

    /// Verify the CATREPLAY claim for token replay protection
    fn verify_catreplay_claim(&self, options: &VerificationOptions) -> Result<(), Error> {
        use crate::constants::{cat_keys, replay_values};

        // Check if token has CATREPLAY claim
        let catreplay_claim = match self.claims.custom.get(&cat_keys::CATREPLAY) {
            Some(claim) => claim,
            None => return Ok(()), // No CATREPLAY claim, so nothing to verify
        };

        // Get the replay protection value
        let replay_value = match catreplay_claim {
            CborValue::Integer(value) => *value as i32,
            _ => {
                return Err(Error::InvalidClaimValue(
                    "CATREPLAY claim is not an integer".to_string(),
                ))
            }
        };

        match replay_value {
            replay_values::PERMITTED => {
                // Replay is permitted, no verification needed
                Ok(())
            }
            replay_values::PROHIBITED => {
                // Replay is prohibited, check if token has been seen before
                if options.token_seen_before {
                    Err(Error::ReplayViolation(
                        "Token replay is prohibited".to_string(),
                    ))
                } else {
                    Ok(())
                }
            }
            replay_values::REUSE_DETECTION => {
                // Reuse is detected but allowed, no error returned
                // Implementations should log or notify about reuse
                Ok(())
            }
            _ => Err(Error::InvalidClaimValue(format!(
                "Invalid CATREPLAY value: {}",
                replay_value
            ))),
        }
    }

    /// Get the signature input (data that was signed)
    fn signature_input(&self, variant: &MacType) -> Result<Vec<u8>, Error> {
        match variant {
            MacType::SIGN1(_) => self.sign1_input(),
            MacType::MAC0(_) => self.mac0_input(),
        }
    }

    /// Get the COSE_Sign1 signature input
    fn sign1_input(&self) -> Result<Vec<u8>, Error> {
        // Sig_structure = [
        //   context : "Signature1",
        //   protected : bstr .cbor header_map,
        //   external_aad : bstr,
        //   payload : bstr .cbor claims
        // ]

        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);

        // Start array with 4 items
        enc.array(4)?;

        // 1. Context
        enc.str("Signature1")?;

        // 2. Protected header
        let protected_bytes = encode_map(&self.header.protected)?;
        enc.bytes(&protected_bytes)?;

        // 3. External AAD (empty in our case)
        enc.bytes(&[])?;

        // 4. Payload
        let claims_map = self.claims.to_map();
        let claims_bytes = encode_map(&claims_map)?;
        enc.bytes(&claims_bytes)?;

        Ok(buf)
    }

    /// Get the COSE_Mac0 signature input
    fn mac0_input(&self) -> Result<Vec<u8>, Error> {
        // Mac_structure = [
        //   context : "MAC0",
        //   protected : bstr .cbor header_map,
        //   external_aad : bstr,
        //   payload : bstr .cbor claims
        // ]

        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);

        // Start array with 4 items
        enc.array(4)?;

        // 1. Context
        enc.str("MAC0")?;

        // 2. Protected header
        let protected_bytes = encode_map(&self.header.protected)?;
        enc.bytes(&protected_bytes)?;

        // 3. External AAD (empty in our case)
        enc.bytes(&[])?;

        // 4. Payload
        let claims_map = self.claims.to_map();
        let claims_bytes = encode_map(&claims_map)?;
        enc.bytes(&claims_bytes)?;

        Ok(buf)
    }
}

/// Options for token verification
#[derive(Debug, Clone, Default)]
pub struct VerificationOptions {
    /// Verify expiration claim
    pub verify_exp: bool,
    /// Require expiration claim
    pub require_exp: bool,
    /// Verify not before claim
    pub verify_nbf: bool,
    /// Expected issuer
    pub expected_issuer: Option<String>,
    /// Require issuer claim
    pub require_iss: bool,
    /// Expected audience
    pub expected_audience: Option<String>,
    /// Require audience claim
    pub require_aud: bool,
    /// Verify CAT-specific URI claim (CATU) against provided URI
    pub verify_catu: bool,
    /// URI to verify against CATU claim
    pub uri: Option<String>,
    /// Verify CAT-specific HTTP methods claim (CATM) against provided method
    pub verify_catm: bool,
    /// HTTP method to verify against CATM claim
    pub http_method: Option<String>,
    /// Verify CAT-specific replay protection (CATREPLAY)
    pub verify_catreplay: bool,
    /// Whether the token has been seen before (for replay protection)
    pub token_seen_before: bool,
}

impl VerificationOptions {
    /// Create new default verification options
    pub fn new() -> Self {
        Self {
            verify_exp: true,
            require_exp: false,
            verify_nbf: true,
            expected_issuer: None,
            require_iss: false,
            expected_audience: None,
            require_aud: false,
            verify_catu: false,
            uri: None,
            verify_catm: false,
            http_method: None,
            verify_catreplay: false,
            token_seen_before: false,
        }
    }

    /// Set whether to verify expiration
    pub fn verify_exp(mut self, verify: bool) -> Self {
        self.verify_exp = verify;
        self
    }

    /// Set whether to require expiration
    pub fn require_exp(mut self, require: bool) -> Self {
        self.require_exp = require;
        self
    }

    /// Set whether to verify not before
    pub fn verify_nbf(mut self, verify: bool) -> Self {
        self.verify_nbf = verify;
        self
    }

    /// Set expected issuer
    pub fn expected_issuer<S: Into<String>>(mut self, issuer: S) -> Self {
        self.expected_issuer = Some(issuer.into());
        self
    }

    /// Set whether to require issuer
    pub fn require_iss(mut self, require: bool) -> Self {
        self.require_iss = require;
        self
    }

    /// Set expected audience
    pub fn expected_audience<S: Into<String>>(mut self, audience: S) -> Self {
        self.expected_audience = Some(audience.into());
        self
    }

    /// Set whether to require audience
    pub fn require_aud(mut self, require: bool) -> Self {
        self.require_aud = require;
        self
    }

    /// Set whether to verify CAT-specific URI claim (CATU)
    pub fn verify_catu(mut self, verify: bool) -> Self {
        self.verify_catu = verify;
        self
    }

    /// Set URI to verify against CATU claim
    pub fn uri<S: Into<String>>(mut self, uri: S) -> Self {
        self.uri = Some(uri.into());
        self
    }

    /// Set whether to verify CAT-specific HTTP methods claim (CATM)
    pub fn verify_catm(mut self, verify: bool) -> Self {
        self.verify_catm = verify;
        self
    }

    /// Set HTTP method to verify against CATM claim
    pub fn http_method<S: Into<String>>(mut self, method: S) -> Self {
        self.http_method = Some(method.into());
        self
    }

    /// Set whether to verify CAT-specific replay protection (CATREPLAY)
    pub fn verify_catreplay(mut self, verify: bool) -> Self {
        self.verify_catreplay = verify;
        self
    }

    /// Set whether the token has been seen before (for replay protection)
    pub fn token_seen_before(mut self, seen: bool) -> Self {
        self.token_seen_before = seen;
        self
    }
}
// Specify what type of COSE sign to use
// and indicate if cose tag should be added
#[derive(Debug, Clone)]
pub enum MacType {
    MAC0(bool),
    SIGN1(bool),
}

impl Default for MacType {
    fn default() -> Self {
        MacType::SIGN1(false)
    }
}
/// Builder for creating tokens
#[derive(Debug, Clone, Default)]
pub struct TokenBuilder {
    header: Header,
    claims: Claims,
    use_cwt_tag: bool,
    mac_type: MacType,
}
impl TokenBuilder {
    /// Create a new token builder
    pub fn new() -> Self {
        Self::default()
    }
    // select either mach or mach0, defaults to mach
    pub fn mac_type(mut self, variant: MacType) -> Self {
        self.mac_type = variant;
        self
    }
    // if the optional CWT tag should be added to the token
    pub fn use_cwt_tag(mut self, cwt_tag: bool) -> Self {
        self.use_cwt_tag = cwt_tag;
        self
    }
    /// Set the algorithm
    pub fn algorithm(mut self, alg: Algorithm) -> Self {
        self.header = self.header.with_algorithm(alg);
        self
    }

    /// Set the key identifier in the protected header
    pub fn protected_key_id(mut self, kid: KeyId) -> Self {
        self.header = self.header.with_protected_key_id(kid);
        self
    }

    /// Set the key identifier in the unprotected header
    pub fn unprotected_key_id(mut self, kid: KeyId) -> Self {
        self.header = self.header.with_unprotected_key_id(kid);
        self
    }

    /// Set the registered claims
    pub fn registered_claims(mut self, claims: RegisteredClaims) -> Self {
        self.claims = self.claims.with_registered_claims(claims);
        self
    }

    /// Add a custom claim with a string value
    pub fn custom_string<S: Into<String>>(mut self, key: i32, value: S) -> Self {
        self.claims = self.claims.with_custom_string(key, value);
        self
    }

    /// Add a custom claim with a binary value
    pub fn custom_binary<B: Into<Vec<u8>>>(mut self, key: i32, value: B) -> Self {
        self.claims = self.claims.with_custom_binary(key, value);
        self
    }

    /// Add a custom claim with an integer value
    pub fn custom_int(mut self, key: i32, value: i64) -> Self {
        self.claims = self.claims.with_custom_int(key, value);
        self
    }

    /// Add a custom claim with a nested map value
    pub fn custom_map(mut self, key: i32, value: BTreeMap<i32, CborValue>) -> Self {
        self.claims = self.claims.with_custom_map(key, value);
        self
    }

    /// Add a custom claim with a CborValue directly
    pub fn custom_cbor(mut self, key: i32, value: CborValue) -> Self {
        self.claims.custom.insert(key, value);
        self
    }

    /// Add a custom claim with an array value
    pub fn custom_array(mut self, key: i32, value: Vec<CborValue>) -> Self {
        self.claims.custom.insert(key, CborValue::Array(value));
        self
    }

    /// Build and sign the token
    pub fn sign(self, key: &[u8]) -> Result<Token, Error> {
        // Ensure we have an algorithm
        let alg = self.header.algorithm().ok_or_else(|| {
            Error::InvalidFormat("Missing algorithm in protected header".to_string())
        })?;
        // Create token without signature
        let token = Token {
            header: self.header,
            claims: self.claims,
            signature: Vec::new(),
            cwt: self.use_cwt_tag,
            mac_type: None,
        };

        // Compute signature input
        let signature_input = token.signature_input(&self.mac_type)?;

        // Sign based on algorithm
        let signature = match alg {
            Algorithm::HmacSha256 => compute_hmac_sha256(key, &signature_input),
        };

        // Create final token with signature
        Ok(Token {
            header: token.header,
            claims: token.claims,
            signature,
            cwt: self.use_cwt_tag,
            mac_type: Some(self.mac_type),
        })
    }
}

// Helper functions for CBOR encoding/decoding

fn encode_map(map: &HeaderMap) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);

    encode_map_direct(map, &mut enc)?;

    Ok(buf)
}

/// Encode a CBOR value directly to the encoder
fn encode_cbor_value(value: &CborValue, enc: &mut Encoder<&mut Vec<u8>>) -> Result<(), Error> {
    match value {
        CborValue::Integer(i) => {
            enc.i64(*i)?;
        }
        CborValue::Bytes(b) => {
            enc.bytes(b)?;
        }
        CborValue::Text(s) => {
            enc.str(s)?;
        }
        CborValue::Map(nested_map) => {
            // Create a nested encoder for the map
            encode_map_direct(nested_map, enc)?;
        }
        CborValue::Array(arr) => {
            // Create a nested encoder for the array
            enc.array(arr.len() as u64)?;
            for item in arr {
                encode_cbor_value(item, enc)?;
            }
        }
        CborValue::Null => {
            enc.null()?;
        }
    }
    Ok(())
}

fn encode_map_direct(map: &HeaderMap, enc: &mut Encoder<&mut Vec<u8>>) -> Result<(), Error> {
    enc.map(map.len() as u64)?;

    for (key, value) in map {
        enc.i32(*key)?;
        encode_cbor_value(value, enc)?;
    }

    Ok(())
}

fn decode_map(bytes: &[u8]) -> Result<HeaderMap, Error> {
    let mut dec = Decoder::new(bytes);
    decode_map_direct(&mut dec)
}

/// Decode a CBOR array
fn decode_array(dec: &mut Decoder<'_>) -> Result<Vec<CborValue>, Error> {
    let array_len = dec.array()?.unwrap_or(0);
    let mut array = Vec::with_capacity(array_len as usize);

    for _ in 0..array_len {
        // Try to decode based on the datatype
        let datatype = dec.datatype()?;

        // Handle each type separately
        let value = if datatype == minicbor::data::Type::Int {
            // Integer value
            let i = dec.i64()?;
            CborValue::Integer(i)
        } else if datatype == minicbor::data::Type::U8
            || datatype == minicbor::data::Type::U16
            || datatype == minicbor::data::Type::U32
            || datatype == minicbor::data::Type::U64
        {
            // Unsigned integer value
            let i = dec.u64()? as i64;
            CborValue::Integer(i)
        } else if datatype == minicbor::data::Type::Bytes {
            // Byte string
            let b = dec.bytes()?;
            CborValue::Bytes(b.to_vec())
        } else if datatype == minicbor::data::Type::String {
            // Text string
            let s = dec.str()?;
            CborValue::Text(s.to_string())
        } else if datatype == minicbor::data::Type::Map {
            // Nested map
            let nested_map = decode_map_direct(dec)?;
            CborValue::Map(nested_map)
        } else if datatype == minicbor::data::Type::Array {
            // Nested array
            let nested_array = decode_array(dec)?;
            CborValue::Array(nested_array)
        } else if datatype == minicbor::data::Type::Null {
            // Null value
            dec.null()?;
            CborValue::Null
        } else {
            // Unsupported type
            return Err(Error::InvalidFormat(format!(
                "Unsupported CBOR type in array: {:?}",
                datatype
            )));
        };

        array.push(value);
    }

    Ok(array)
}

fn decode_map_direct(dec: &mut Decoder<'_>) -> Result<HeaderMap, Error> {
    let map_len = dec.map()?.unwrap_or(0);
    let mut map = HeaderMap::new();

    for _ in 0..map_len {
        let key = dec.i32()?;

        // Try to decode based on the datatype
        let datatype = dec.datatype()?;

        // Handle each type separately
        let value = if datatype == minicbor::data::Type::Int {
            // Integer value
            let i = dec.i64()?;
            CborValue::Integer(i)
        } else if datatype == minicbor::data::Type::U8
            || datatype == minicbor::data::Type::U16
            || datatype == minicbor::data::Type::U32
            || datatype == minicbor::data::Type::U64
        {
            // Unsigned integer value
            let i = dec.u64()? as i64;
            CborValue::Integer(i)
        } else if datatype == minicbor::data::Type::Bytes {
            // Byte string
            let b = dec.bytes()?;
            CborValue::Bytes(b.to_vec())
        } else if datatype == minicbor::data::Type::String {
            // Text string
            let s = dec.str()?;
            CborValue::Text(s.to_string())
        } else if datatype == minicbor::data::Type::Map {
            // Nested map
            let nested_map = decode_map_direct(dec)?;
            CborValue::Map(nested_map)
        } else if datatype == minicbor::data::Type::Array {
            // Array
            let array = decode_array(dec)?;
            CborValue::Array(array)
        } else if datatype == minicbor::data::Type::Null {
            // Null value
            dec.null()?;
            CborValue::Null
        } else {
            // Unsupported type
            return Err(Error::InvalidFormat(format!(
                "Unsupported CBOR type: {:?}",
                datatype
            )));
        };

        map.insert(key, value);
    }

    Ok(map)
}
