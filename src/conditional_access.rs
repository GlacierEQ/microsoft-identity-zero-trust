/// Conditional Access Policy Engine for Microsoft Identity Zero Trust
/// Evaluates real-time access policies based on device, location, and risk signals.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct AccessPolicy {
    pub name: String,
    pub require_mfa: bool,
    pub require_compliant_device: bool,
    pub allowed_locations: Vec<String>,
    pub max_risk_score: f32,
    pub block_legacy_auth: bool,
}

#[derive(Debug, Clone)]
pub struct AccessContext {
    pub device_id: String,
    pub device_compliant: bool,
    pub ip_address: String,
    pub location: String,
    pub risk_score: f32,
    pub auth_protocol: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AccessDecision {
    Allow,
    Deny(String),           // Reason for denial
    RequireMfa,             // Conditional grant
    RequireCompliantDevice, // Conditional grant
}

pub struct ConditionalAccessEngine {
    policies: Vec<AccessPolicy>,
    location_cache: HashMap<String, String>, // ip -> country/region
}

impl ConditionalAccessEngine {
    pub fn new() -> Self {
        ConditionalAccessEngine {
            policies: Vec::new(),
            location_cache: HashMap::new(),
        }
    }

    pub fn add_policy(&mut self, policy: AccessPolicy) {
        self.policies.push(policy);
    }

    /// Evaluate all policies against the access context.
    /// Returns the most restrictive decision.
    pub fn evaluate(&self, ctx: &AccessContext) -> AccessDecision {
        let mut decision = AccessDecision::Allow;

        for policy in &self.policies {
            // Block legacy auth if policy requires it
            if policy.block_legacy_auth && self.is_legacy_auth(&ctx.auth_protocol) {
                return AccessDecision::Deny(
                    format!("Legacy auth blocked by policy: {}", policy.name)
                );
            }

            // Location-based block
            if !policy.allowed_locations.is_empty()
                && !policy.allowed_locations.contains(&ctx.location) {
                return AccessDecision::Deny(
                    format!("Location '{}' blocked by policy: {}", ctx.location, policy.name)
                );
            }

            // Risk score threshold
            if ctx.risk_score > policy.max_risk_score {
                return AccessDecision::Deny(
                    format!("Risk score {:.2} exceeds threshold {:.2} in policy: {}",
                            ctx.risk_score, policy.max_risk_score, policy.name)
                );
            }

            // Conditional grants (MFA, compliant device)
            if policy.require_mfa && !self.has_mfa_evidence(ctx) {
                decision = AccessDecision::RequireMfa;
            }
            if policy.require_compliant_device && !ctx.device_compliant {
                decision = AccessDecision::RequireCompliantDevice;
            }
        }

        decision
    }

    fn is_legacy_auth(&self, protocol: &str) -> bool {
        matches!(protocol, "NTLM" | "Kerberos" | "Basic" | "Digest")
    }

    fn has_mfa_evidence(&self, ctx: &AccessContext) -> bool {
        // Placeholder: in production, check token claims for amr == ["mfa"]
        ctx.auth_protocol == "OAuth2+MFA" || ctx.auth_protocol == "SAML+MFA"
    }

    /// Cache IP -> location mapping (would call GeoIP service in production)
    pub fn update_location(&mut self, ip: String, location: String) {
        self.location_cache.insert(ip, location);
    }
}

impl Default for ConditionalAccessEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_auth_blocked() {
        let mut engine = ConditionalAccessEngine::new();
        engine.add_policy(AccessPolicy {
            name: "Block Legacy".into(),
            require_mfa: false,
            require_compliant_device: false,
            allowed_locations: vec![],
            max_risk_score: 1.0,
            block_legacy_auth: true,
        });

        let ctx = AccessContext {
            device_id: "dev-001".into(),
            device_compliant: true,
            ip_address: "10.0.0.1".into(),
            location: "US".into(),
            risk_score: 0.1,
            auth_protocol: "NTLM".into(),
        };

        assert!(matches!(engine.evaluate(&ctx), AccessDecision::Deny(_)));
    }

    #[test]
    fn test_location_block() {
        let mut engine = ConditionalAccessEngine::new();
        engine.add_policy(AccessPolicy {
            name: "US Only".into(),
            require_mfa: false,
            require_compliant_device: false,
            allowed_locations: vec!["US".into()],
            max_risk_score: 1.0,
            block_legacy_auth: false,
        });

        let ctx = AccessContext {
            device_id: "dev-001".into(),
            device_compliant: true,
            ip_address: "10.0.0.1".into(),
            location: "CN".into(),
            risk_score: 0.1,
            auth_protocol: "OAuth2".into(),
        };

        assert!(matches!(engine.evaluate(&ctx), AccessDecision::Deny(_)));
    }

    #[test]
    fn test_mfa_required() {
        let mut engine = ConditionalAccessEngine::new();
        engine.add_policy(AccessPolicy {
            name: "MFA Required".into(),
            require_mfa: true,
            require_compliant_device: false,
            allowed_locations: vec![],
            max_risk_score: 1.0,
            block_legacy_auth: false,
        });

        let ctx = AccessContext {
            device_id: "dev-001".into(),
            device_compliant: true,
            ip_address: "10.0.0.1".into(),
            location: "US".into(),
            risk_score: 0.1,
            auth_protocol: "OAuth2".into(),
        };

        assert_eq!(engine.evaluate(&ctx), AccessDecision::RequireMfa);
    }
}