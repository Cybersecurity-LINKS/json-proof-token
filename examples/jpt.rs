use std::collections::HashMap;

use jsonprooftoken::{jpt::claims::JptClaims, jwp::{header::{IssuerProtectedHeader, PresentationProtectedHeader}, issued::JwpIssued, presented::JwpPresented}, jpa::algs::ProofAlgorithm, encoding::{base64url_encode, SerializationType}, jwk::{key::Jwk, types::KeyPairSubtype, alg_parameters::JwkAlgorithmParameters}};
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
    
    let compact_issued_jwp = issued_jwp.encode(SerializationType::COMPACT, &bbs_jwk).unwrap();
    println!("Compact JWP: {}", compact_issued_jwp);

    let decoded_issued_jwp = JwpIssued::decode(compact_issued_jwp, SerializationType::COMPACT, &bbs_jwk.to_public().unwrap()).unwrap();

    println!("DECODED ISSUED JWP \n{:?}", decoded_issued_jwp);


    let presentation_header = PresentationProtectedHeader{
        alg: ProofAlgorithm::BLS12381_SHA256_PROOF,
        aud: Some("https://recipient.example.com".to_owned()),
        nonce: Some("wrmBRkKtXjQ".to_owned())
    };

    
    // This is an alternative
    // let presentation_jwp = decoded_issued_jwp.present(SerializationType::COMPACT, &bbs_jwk.to_public().unwrap(), presentation_header);
    
    
    let mut presentation_jwp = JwpPresented::new(decoded_issued_jwp.get_issuer_protected_header().clone(),presentation_header, decoded_issued_jwp.get_payloads().clone());
    presentation_jwp.set_disclosed(1, false).unwrap();
    presentation_jwp.set_disclosed(3, false).unwrap();

    let compact_presented_jwp = presentation_jwp.encode(SerializationType::COMPACT, &bbs_jwk.to_public().unwrap(), decoded_issued_jwp.get_proof().unwrap()).unwrap();

    println!("Compact Presented JWP: {}", compact_presented_jwp);

    let decoded_presentation_jwp = JwpPresented::decode(compact_presented_jwp, SerializationType::COMPACT, &bbs_jwk.to_public().unwrap()).unwrap();
    println!("DECODED PRESENTED JWP \n{:?}", decoded_presentation_jwp);



    

    // let original = JptClaims::reconstruct_json_value(claims);
    // println!("{:?}", original);
    

    // let claims_map = jpt_claims.to_map();
    // println!("{:?}", claims_map);


    // let deserialized = JptClaims::from_map(claims_map);

    // println!("{:?}", jpt_claims);
    // println!("{:?}", deserialized);
}
