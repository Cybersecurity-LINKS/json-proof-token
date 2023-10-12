use std::collections::HashMap;

use jsonprooftoken::{jpt::claims::JptClaims, jwp::{header::IssuerProtectedHeader, issued::JwpIssuedForm}, jpa::algs::ProofAlgorithm};
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

    let jpt_claims = JptClaims {
        sub: Some("user123".to_string()),
        exp: Some(1633756800),
        nbf: None,
        iat: None,
        jti: None,
        custom: Some(serde_json::json!({
            "family_name": "Doe",
            "given_name": "Jay",
            "email": "jaydoe@example.org",
            "age": 42
        }))
    };

    
    println!("{:?}", jpt_claims);
    let (claims, payloads) = jpt_claims.get_claims_and_payloads();

    println!("Claims: {:?}", claims);
    println!("Payloads: {:?}", payloads);


    let issued_header = IssuerProtectedHeader{
        typ: Some("JPT".to_owned()),
        alg: ProofAlgorithm::BLS12381_SHA256,
        iss: None,
        cid: None,
        claims: Some(claims),
    };

    let issued_jwp = JwpIssuedForm::new(issued_header, payloads);


    // let original = JptClaims::reconstruct_json_value(claims);
    // println!("{:?}", original);
    

    // let claims_map = jpt_claims.to_map();
    // println!("{:?}", claims_map);


    // let deserialized = JptClaims::from_map(claims_map);

    // println!("{:?}", jpt_claims);
    // println!("{:?}", deserialized);
}
