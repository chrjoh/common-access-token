//! # CAT-specific Claims
//!
//! This module provides helper functions and structures for working with
//! Common Access Token (CAT) specific claims as defined in the CAT specification.
//!
//! These claims include:
//! - CATU (Common Access Token URI) - limits the URI to which the token can provide access
//! - CATR (Common Access Token Renewal) - instructions for token renewal
//! - CATM (Common Access Token Methods) - limits HTTP methods
//! - CATREPLAY - controls token replay behavior
//! - CATALPN (Common Access Token ALPN) - limits TLS ALPNs
//! - And others like CATV, CATNIP, CATGEO, etc.
//!
//! ## CATU Claim (URI Validation)
//!
//! The CATU claim allows you to specify URI component restrictions. For example:
//!
//! ```rust
//! use common_access_token::{catu, uri_components, cat_keys};
//! use std::collections::BTreeMap;
//!
//! // Create a CATU claim for URI validation
//! let mut catu_components = BTreeMap::new();
//!
//! // Restrict to https scheme
//! catu_components.insert(uri_components::SCHEME, catu::exact_match("https"));
//!
//! // Restrict to example.com host
//! catu_components.insert(uri_components::HOST, catu::suffix_match(".example.com"));
//!
//! // Restrict to paths starting with /api
//! catu_components.insert(uri_components::PATH, catu::prefix_match("/api"));
//!
//! // Create the CATU claim
//! let catu_claim = catu::create(catu_components);
//! ```
//!
//! ## CATM Claim (HTTP Methods)
//!
//! The CATM claim restricts which HTTP methods are allowed:
//!
//! ```rust
//! use common_access_token::{catm, cat_keys};
//!
//! // Create a CATM claim allowing only GET and HEAD methods
//! let allowed_methods = vec!["GET", "HEAD"];
//! let catm_claim = catm::create(allowed_methods);
//! ```
//!
//! ## CATREPLAY Claim (Replay Protection)
//!
//! The CATREPLAY claim controls token replay behavior:
//!
//! ```rust
//! use common_access_token::{catreplay, cat_keys};
//!
//! // Create a CATREPLAY claim that prohibits token reuse
//! let catreplay_claim = catreplay::prohibited();
//!
//! // Or allow token reuse
//! let catreplay_permitted = catreplay::permitted();
//!
//! // Or enable reuse detection
//! let catreplay_detect = catreplay::reuse_detection();
//! ```
//!
//! ## CATR Claim (Token Renewal)
//!
//! The CATR claim provides instructions for token renewal:
//!
//! ```rust
//! use common_access_token::{catr, cat_keys};
//! use common_access_token::current_timestamp;
//!
//! let now = current_timestamp();
//!
//! // Create an automatic renewal claim
//! // This extends expiration by 3600 seconds with a deadline 3000 seconds from now
//! let renewal_params = catr::automatic_renewal(3600, Some((now + 3000) as i64));
//! let catr_claim = catr::create(renewal_params);
//!
//! // Or create a cookie-based renewal claim
//! let cookie_renewal = catr::cookie_renewal(
//!     3600,
//!     Some((now + 3000) as i64),
//!     Some("session"),
//!     Some(vec!["Secure", "HttpOnly"])
//! );
//! ```

use crate::header::CborValue;
use std::collections::BTreeMap;

/// CAT-specific claim keys
pub mod keys {
    use crate::constants::cat_keys;

    /// Common Access Token Replay (catreplay) claim key
    pub const CATREPLAY: i32 = cat_keys::CATREPLAY;
    /// Common Access Token Probability of Rejection (catpor) claim key
    pub const CATPOR: i32 = cat_keys::CATPOR;
    /// Common Access Token Version (catv) claim key
    pub const CATV: i32 = cat_keys::CATV;
    /// Common Access Token Network IP (catnip) claim key
    pub const CATNIP: i32 = cat_keys::CATNIP;
    /// Common Access Token URI (catu) claim key
    pub const CATU: i32 = cat_keys::CATU;
    /// Common Access Token Methods (catm) claim key
    pub const CATM: i32 = cat_keys::CATM;
    /// Common Access Token ALPN (catalpn) claim key
    pub const CATALPN: i32 = cat_keys::CATALPN;
    /// Common Access Token Header (cath) claim key
    pub const CATH: i32 = cat_keys::CATH;
    /// Common Access Token Geographic ISO3166 (catgeoiso3166) claim key
    pub const CATGEOISO3166: i32 = cat_keys::CATGEOISO3166;
    /// Common Access Token Geographic Coordinate (catgeocoord) claim key
    pub const CATGEOCOORD: i32 = cat_keys::CATGEOCOORD;
    /// Common Access Token Altitude (catgeoalt) claim key
    pub const CATGEOALT: i32 = cat_keys::CATGEOALT;
    /// Common Access Token TLS Public Key (cattpk) claim key
    pub const CATTPK: i32 = cat_keys::CATTPK;
    /// Common Access Token If Data (catifdata) claim key
    pub const CATIFDATA: i32 = cat_keys::CATIFDATA;
    /// Common Access Token DPoP Settings (catdpop) claim key
    pub const CATDPOP: i32 = cat_keys::CATDPOP;
    /// Common Access Token If (catif) claim key
    pub const CATIF: i32 = cat_keys::CATIF;
    /// Common Access Token Renewal (catr) claim key
    pub const CATR: i32 = cat_keys::CATR;
}

/// Helper functions for creating CATU (Common Access Token URI) claims
pub mod catu {
    use super::*;
    use crate::constants::match_types;

    /// Creates a CATU claim with the specified URI component restrictions
    pub fn create(components: BTreeMap<i32, BTreeMap<i32, CborValue>>) -> CborValue {
        let mut map = BTreeMap::new();
        for (component_key, match_map) in components {
            let mut inner_map = BTreeMap::new();
            for (match_type, match_value) in match_map {
                inner_map.insert(match_type, match_value);
            }
            map.insert(component_key, CborValue::Map(inner_map));
        }
        CborValue::Map(map)
    }

    /// Creates a match condition for exact text matching
    pub fn exact_match(text: &str) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(match_types::EXACT, CborValue::Text(text.to_string()));
        map
    }

    /// Creates a match condition for prefix matching
    pub fn prefix_match(prefix: &str) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(match_types::PREFIX, CborValue::Text(prefix.to_string()));
        map
    }

    /// Creates a match condition for suffix matching
    pub fn suffix_match(suffix: &str) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(match_types::SUFFIX, CborValue::Text(suffix.to_string()));
        map
    }

    /// Creates a match condition for contains matching
    pub fn contains_match(text: &str) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(match_types::CONTAINS, CborValue::Text(text.to_string()));
        map
    }

    /// Creates a match condition for regex matching
    pub fn regex_match(pattern: &str, groups: Vec<Option<String>>) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();

        let mut array = vec![CborValue::Text(pattern.to_string())];
        for group in groups {
            match group {
                Some(text) => array.push(CborValue::Text(text)),
                None => array.push(CborValue::Null),
            }
        }

        map.insert(match_types::REGEX, CborValue::Array(array));
        map
    }

    /// Creates a match condition for SHA-256 matching
    pub fn sha256_match(hash: Vec<u8>) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(match_types::SHA256, CborValue::Bytes(hash));
        map
    }

    /// Creates a match condition for SHA-512/256 matching
    pub fn sha512_256_match(hash: Vec<u8>) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(match_types::SHA512_256, CborValue::Bytes(hash));
        map
    }
}

/// Helper functions for creating CATR (Common Access Token Renewal) claims
pub mod catr {
    use super::*;
    use crate::constants::{renewal_params, renewal_types};

    /// Creates a CATR claim with the specified renewal parameters
    pub fn create(params: BTreeMap<i32, CborValue>) -> CborValue {
        CborValue::Map(params)
    }

    /// Creates an automatic renewal claim
    pub fn automatic_renewal(exp_add: i64, deadline: Option<i64>) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(
            renewal_params::TYPE,
            CborValue::Integer(renewal_types::AUTOMATIC as i64),
        );
        map.insert(renewal_params::EXPADD, CborValue::Integer(exp_add));

        if let Some(deadline_value) = deadline {
            map.insert(renewal_params::DEADLINE, CborValue::Integer(deadline_value));
        }

        map
    }

    /// Creates a cookie renewal claim
    pub fn cookie_renewal(
        exp_add: i64,
        deadline: Option<i64>,
        cookie_name: Option<&str>,
        additional_params: Option<Vec<&str>>,
    ) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(
            renewal_params::TYPE,
            CborValue::Integer(renewal_types::COOKIE as i64),
        );
        map.insert(renewal_params::EXPADD, CborValue::Integer(exp_add));

        if let Some(deadline_value) = deadline {
            map.insert(renewal_params::DEADLINE, CborValue::Integer(deadline_value));
        }

        if let Some(name) = cookie_name {
            map.insert(
                renewal_params::COOKIE_NAME,
                CborValue::Text(name.to_string()),
            );
        }

        if let Some(params) = additional_params {
            let params_array: Vec<CborValue> = params
                .into_iter()
                .map(|s| CborValue::Text(s.to_string()))
                .collect();
            map.insert(
                renewal_params::COOKIE_PARAMS,
                CborValue::Array(params_array),
            );
        }

        map
    }

    /// Creates a header renewal claim
    pub fn header_renewal(
        exp_add: i64,
        deadline: Option<i64>,
        header_name: Option<&str>,
        additional_params: Option<Vec<&str>>,
    ) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(
            renewal_params::TYPE,
            CborValue::Integer(renewal_types::HEADER as i64),
        );
        map.insert(renewal_params::EXPADD, CborValue::Integer(exp_add));

        if let Some(deadline_value) = deadline {
            map.insert(renewal_params::DEADLINE, CborValue::Integer(deadline_value));
        }

        if let Some(name) = header_name {
            map.insert(
                renewal_params::HEADER_NAME,
                CborValue::Text(name.to_string()),
            );
        }

        if let Some(params) = additional_params {
            let params_array: Vec<CborValue> = params
                .into_iter()
                .map(|s| CborValue::Text(s.to_string()))
                .collect();
            map.insert(
                renewal_params::HEADER_PARAMS,
                CborValue::Array(params_array),
            );
        }

        map
    }

    /// Creates a redirect renewal claim
    pub fn redirect_renewal(
        exp_add: i64,
        deadline: Option<i64>,
        status_code: Option<i64>,
    ) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(
            renewal_params::TYPE,
            CborValue::Integer(renewal_types::REDIRECT as i64),
        );
        map.insert(renewal_params::EXPADD, CborValue::Integer(exp_add));

        if let Some(deadline_value) = deadline {
            map.insert(renewal_params::DEADLINE, CborValue::Integer(deadline_value));
        }

        if let Some(code) = status_code {
            map.insert(renewal_params::STATUS_CODE, CborValue::Integer(code));
        }

        map
    }
}

/// Helper functions for creating CATM (Common Access Token Methods) claims
pub mod catm {
    use super::*;

    /// Creates a CATM claim with the specified HTTP methods
    pub fn create(methods: Vec<&str>) -> Vec<CborValue> {
        methods
            .into_iter()
            .map(|s| CborValue::Text(s.to_string()))
            .collect()
    }
}

/// Helper functions for creating CATREPLAY claims
pub mod catreplay {
    use super::*;
    use crate::constants::replay_values;

    /// Creates a CATREPLAY claim with the specified value
    pub fn create(value: i32) -> CborValue {
        CborValue::Integer(value as i64)
    }

    /// Creates a CATREPLAY claim with "permitted" value
    pub fn permitted() -> CborValue {
        CborValue::Integer(replay_values::PERMITTED as i64)
    }

    /// Creates a CATREPLAY claim with "prohibited" value
    pub fn prohibited() -> CborValue {
        CborValue::Integer(replay_values::PROHIBITED as i64)
    }

    /// Creates a CATREPLAY claim with "reuse detection" value
    pub fn reuse_detection() -> CborValue {
        CborValue::Integer(replay_values::REUSE_DETECTION as i64)
    }
}

/// Helper functions for creating CATV (Common Access Token Version) claims
pub mod catv {
    use super::*;

    /// Creates a CATV claim with version 1
    pub fn create() -> CborValue {
        CborValue::Integer(1)
    }
}
