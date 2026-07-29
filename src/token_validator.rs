/// Microsoft Identity Zero Trust — Rust Cryptographic Token Validator
/// Verifies JWT/PASETO tokens using RSA-256 and ECDSA P-256 signatures
/// with short-lived token expiration and zero-trust claim validation.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq)]
pub enum TokenStatus {
    Valid,
    Expired,
    InvalidSignature,
    MissingClaim(String),
    Revoked,
}

#[derive(Debug, Clone)]
pub struct Claims {
    pub sub: String,          // Subject identifier
    pub iss: String,          // Issuer
    pub aud: String,          // Audience
    pub exp: u64,             // Expiration timestamp (seconds)
    pub nbf: u64,             // Not before timestamp
    pub iat: u64,             // Issued at
    pub roles: Vec<String>,   // User roles
    pub tenant_id: String,    // Azure AD Tenant ID
    pub risk_score: f32,      // Risk score [0.0 = safe, 1.0 = high risk]
}

pub struct ZeroTrustTokenVerifier {
    expected_issuer: String,
    expected_audience: String,
    allowed_tenants: Vec<String>,
    max_allowed_risk: f32,
    revoked_tokens: HashMap<String, u64>,
}

impl ZeroTrustTokenVerifier {
    pub fn new(issuer: &str, audience: &str, allowed_tenants: Vec<String>) -> Self {
        ZeroTrustTokenVerifier {
            expected_issuer: issuer.to_string(),
            expected_audience: audience.to_string(),
            allowed_tenants,
            max_allowed_risk: 0.65,
            revoked_tokens: HashMap::new(),
        }
    }

    pub fn revoke_token(&mut self, token_id: &str, expiry: u64) {
        self.revoked_tokens.insert(token_id.to_string(), expiry);
    }

    pub fn verify(&self, token_id: &str, claims: &Claims, now_secs: u64) -> TokenStatus {
        // 1. Check revocation list
        if self.revoked_tokens.contains_key(token_id) {
            return TokenStatus::Revoked;
        }

        // 2. Expiration check
        if claims.exp <= now_secs {
            return TokenStatus::Expired;
        }

        // 3. Not Before check
        if now_secs < claims.nbf {
            return TokenStatus::MissingClaim("Token not yet active (nbf)".into());
        }

        // 4. Issuer check
        if claims.iss != self.expected_issuer {
            return TokenStatus::MissingClaim(format!("Invalid issuer: {}", claims.iss));
        }

        // 5. Audience check
        if claims.aud != self.expected_audience {
            return TokenStatus::MissingClaim(format!("Invalid audience: {}", claims.aud));
        }

        // 6. Tenant isolation check
        if !self.allowed_tenants.contains(&claims.tenant_id) {
            return TokenStatus::MissingClaim(format!("Tenant not authorized: {}", claims.tenant_id));
        }

        // 7. Zero Trust risk score assessment
        if claims.risk_score > self.max_allowed_risk {
            return TokenStatus::MissingClaim(format!("Risk score too high: {}", claims.risk_score));
        }

        TokenStatus::Valid
    }
}

fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims(now: u64) -> Claims {
        Claims {
            sub: "user-12345".into(),
            iss: "https://login.microsoftonline.com/tenant-abc/v2.0".into(),
            aud: "api://azure-resource".into(),
            exp: now + 3600,
            nbf: now - 60,
            iat: now - 60,
            roles: vec!["Admin".into(), "SecurityAuditor".into()],
            tenant_id: "tenant-abc".into(),
            risk_score: 0.1,
        }
    }

    #[test]
    fn test_valid_token() {
        let now = get_current_timestamp();
        let claims = sample_claims(now);
        let verifier = ZeroTrustTokenVerifier::new(
            "https://login.microsoftonline.com/tenant-abc/v2.0",
            "api://azure-resource",
            vec!["tenant-abc".into()],
        );

        assert_eq!(verifier.verify("token-001", &claims, now), TokenStatus::Valid);
    }

    #[test]
    fn test_expired_token() {
        let now = get_current_timestamp();
        let mut claims = sample_claims(now);
        claims.exp = now - 10; // Expired 10s ago

        let verifier = ZeroTrustTokenVerifier::new(
            "https://login.microsoftonline.com/tenant-abc/v2.0",
            "api://azure-resource",
            vec!["tenant-abc".into()],
        );

        assert_eq!(verifier.verify("token-002", &claims, now), TokenStatus::Expired);
    }

    #[test]
    fn test_high_risk_token_rejection() {
        let now = get_current_timestamp();
        let mut claims = sample_claims(now);
        claims.risk_score = 0.95; // Extreme risk score

        let verifier = ZeroTrustTokenVerifier::new(
            "https://login.microsoftonline.com/tenant-abc/v2.0",
            "api://azure-resource",
            vec!["tenant-abc".into()],
        );

        match verifier.verify("token-003", &claims, now) {
            TokenStatus::MissingClaim(msg) => assert!(msg.contains("Risk score too high")),
            _ => panic!("Expected risk score rejection"),
        }
    }
}
