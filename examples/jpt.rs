// Copyright 2023 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use jsonprooftoken::{
    encoding::SerializationType,
    jpa::algs::ProofAlgorithm,
    jpt::claims::JptClaims,
    jwk::{key::Jwk, types::KeyPairSubtype},
    jwp::{
        header::{IssuerProtectedHeader, PresentationProtectedHeader},
        issued::{JwpIssuedBuilder, JwpIssuedDecoder},
        presented::{JwpPresentedBuilder, JwpPresentedDecoder},
    },
};

fn main() {
    let custom_claims = serde_json::json!({
        "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Science and Arts",
            "ciao": [
                {"u1": "value1"},
                {"u2": "value2"}
                ]
            },
        "name": "John Doe"
    });

    let mut jpt_claims = JptClaims::new();
    jpt_claims.set_iss("https://issuer.example".to_owned());
    jpt_claims.set_claim(Some("vc"), custom_claims, true);

    let issued_header = IssuerProtectedHeader::new(ProofAlgorithm::BBS);

    let bbs_jwk = Jwk::generate(KeyPairSubtype::BLS12381G2Sha256).unwrap();
    println!(
        "\nBBS Jwk:\n {:#}",
        serde_json::to_string_pretty(&bbs_jwk).unwrap()
    );

    let issued_jwp = JwpIssuedBuilder::new(issued_header, jpt_claims)
        .build(&bbs_jwk)
        .unwrap();

    let compact_issued_jwp = issued_jwp.encode(SerializationType::COMPACT).unwrap();
    println!("\nCompact Issued JWP: {}", compact_issued_jwp);

    let decoded_issued_jwp =
        JwpIssuedDecoder::decode(&compact_issued_jwp, SerializationType::COMPACT)
            .unwrap()
            .verify(&bbs_jwk.to_public().unwrap())
            .unwrap();

    assert_eq!(issued_jwp, decoded_issued_jwp);

    let mut presentation_header = PresentationProtectedHeader::new(
        decoded_issued_jwp
            .get_issuer_protected_header()
            .alg()
            .into(),
    );
    presentation_header.set_aud(Some("https://recipient.example.com".to_owned()));
    presentation_header.set_nonce(Some("wrmBRkKtXjQ".to_owned()));

    let presented_jwp = JwpPresentedBuilder::new(&decoded_issued_jwp)
        .set_presentation_protected_header(presentation_header)
        .set_undisclosed("vc.degree.name")
        .unwrap()
        .set_undisclosed("vc.degree.ciao[0].u1")
        .unwrap()
        .set_undisclosed("vc.name")
        .unwrap()
        .build(&bbs_jwk.to_public().unwrap())
        .unwrap();

    let compact_presented_jwp = presented_jwp.encode(SerializationType::COMPACT).unwrap();

    println!("\nCompact Presented JWP: {}", compact_presented_jwp);

    let _decoded_presented_jwp =
        JwpPresentedDecoder::decode(&compact_presented_jwp, SerializationType::COMPACT)
            .unwrap()
            .verify(&bbs_jwk.to_public().unwrap())
            .unwrap();
}
