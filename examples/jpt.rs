use std::collections::HashMap;

use jsonprooftoken::{jpt::claims::JptClaims, jwp::{header::IssuerProtectedHeader, issued::JwpIssued}, jpa::algs::ProofAlgorithm, encoding::{base64url_encode, SerializationType}, jwk::{key::Jwk, types::KeyPairSubtype, alg_parameters::JwkAlgorithmParameters}};
use serde::Serialize;
use serde_json::Value;


fn main() {

    // let jpt_claims = JptClaims {
    //     sub: Some("user123".to_string()),
    //     exp: Some(1633756800),
    //     nbf: Some(1633670400),
    //     iat: Some(1633666800),
    //     jti: Some("123456".to_string()),
    //     custom: Some(serde_json::json!({
    //         "degree": {
    //             "type": "BachelorDegree",
    //             "name": "Bachelor of Science and Arts",
    //             "ciao": [
    //                 {"u1": "value1"}, 
    //                 {"u2": "value2"}
    //                 ]
    //             },
    //         "name": "John Doe"
    //     })),
    // };

   
    let custom_claims = serde_json::json!({
        "family_name": "Doe",
        "given_name": "Jay",
        "email": "jaydoe@example.org",
        "age": 42
    });



    let mut jpt_claims = JptClaims::new();
    // jpt_claims.add_claim("family_name", "Doe");
    // jpt_claims.add_claim("given_name", "Jay");
    // jpt_claims.add_claim("email", "jaydoe@example.org");
    // jpt_claims.add_claim("age", 42);
    jpt_claims.add_claim("", custom_claims, true);



    
    println!("{:?}", jpt_claims);
    let (claims, payloads) = jpt_claims.get_claims_and_payloads();

    println!("Claims: {:?}", claims);
    println!("Payloads: {:?}", payloads);


    let issued_header = IssuerProtectedHeader{
        typ: Some("JPT".to_owned()),
        alg: ProofAlgorithm::BLS12381_SHA256,
        iss: Some("https://issuer.example".to_owned()),
        cid: None,
        claims: Some(claims),
    };

    println!("Issued Header: {:?}", issued_header);

    let issued_jwp = JwpIssued::new(issued_header, payloads);
    println!("ISSUED JWP: \n{:?}", issued_jwp);


    let bbs_jwk = Jwk::generate(KeyPairSubtype::BLS12381SHA256).unwrap();
    println!("BBS Jwk: {:?}", bbs_jwk);
    
    let compact_jwp = issued_jwp.encode(SerializationType::COMPACT, &bbs_jwk).unwrap();
    println!("Compact JWP: {}", compact_jwp);

    let decoded_jwp = JwpIssued::decode(compact_jwp, SerializationType::COMPACT, &bbs_jwk.to_public().unwrap()).unwrap();

    println!("DECODED ISSUED JWP \n{:?}", decoded_jwp);



    

    // let original = JptClaims::reconstruct_json_value(claims);
    // println!("{:?}", original);
    

    // let claims_map = jpt_claims.to_map();
    // println!("{:?}", claims_map);


    // let deserialized = JptClaims::from_map(claims_map);

    // println!("{:?}", jpt_claims);
    // println!("{:?}", deserialized);
}
