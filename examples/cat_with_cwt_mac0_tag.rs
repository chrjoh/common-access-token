use common_access_token::{
    cat_keys, catr, current_timestamp, token::MacType, Algorithm, KeyId, RegisteredClaims,
    TokenBuilder, VerificationOptions,
};

use hex::FromHex;

fn decode_string(s: &str) -> Vec<u8> {
    let result = Vec::from_hex(s);
    match result {
        Ok(bytes) => bytes,
        Err(_) => panic!("Could not create byte key from string"),
    }
}

fn main() {
    // Create a key for signing and verification
    let key = decode_string("403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388");
    let now = current_timestamp();
    let renewal_params = catr::automatic_renewal(3600, Some((now + 3000) as i64));

    // Create a token with CAT-specific claims
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .unprotected_key_id(KeyId::string("Symmetric256"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("test")
                .with_subject("user_id:asset_id:session_id")
                .with_issued_at(now)
                .with_expiration(now + 3600)
                .with_cti(Vec::from([1, 2, 3, 4])),
        )
        // Add CAT-specific claims
        .custom_cbor(cat_keys::CATR, catr::create(renewal_params))
        .mac_type(MacType::MAC0(true))
        .use_cwt_tag(true)
        .sign(&key)
        .expect("Failed to sign token");

    // Encode token to bytes
    let token_bytes = token.to_bytes().expect("failed to encode token");

    // Decode and verify the token
    let decoded_token =
        common_access_token::Token::from_bytes(&token_bytes).expect("Failed to decode token");

    // Verify signature
    decoded_token
        .verify(&key)
        .expect("Failed to verify signature");

    // Verify standard claims and CAT-specific claims
    let options = VerificationOptions::new()
        .verify_exp(true)
        .expected_issuer("test");

    decoded_token
        .verify_claims(&options)
        .expect("Failed to verify all claims");
}
