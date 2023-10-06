use serde::{Deserialize, Serialize};


/** These claims are taken from the JWT RFC (https://tools.ietf.org/html/rfc7519) 
 * making the hypothesis that in the future will be used also for the JPTs **/

 #[derive(Clone, Debug, Hash, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct JptClaims {

    /// Apparently the "iss" that in JWT was a claim, now should be an issuer protected header parameter 
    /** Apparently the "aud" that in JWT was a claim, now should be an presentation protected header parameter 
      * (https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-proof#name-presentation-protected-head) **/
    
    /// Subject of the JPT.
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    /// Expiration time
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
    /// Time before which the JPT MUST NOT be accepted
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
    /// Issue time
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<i64>,
    /// Unique ID for the JPT.
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
    /// Other claims (age, name, surname, ...)
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    custom: Option<Vec<String>>
}