/// Device Compliance Checker for Microsoft Identity Zero Trust
/// Validates device health, OS version, encryption, and security posture.

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_id: String,
    pub os_type: String,
    pub os_version: String,
    pub disk_encrypted: bool,
    pub secure_boot_enabled: bool,
    pub firewall_enabled: bool,
    pub antivirus_enabled: bool,
    pub last_health_check: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant(Vec<String>), // List of violations
    Unknown,
}

pub struct DeviceComplianceChecker {
    min_os_version: String,
    require_disk_encryption: bool,
    require_secure_boot: bool,
    require_firewall: bool,
    require_antivirus: bool,
}

impl DeviceComplianceChecker {
    pub fn new(
        min_os_version: &str,
        require_disk_encryption: bool,
        require_secure_boot: bool,
        require_firewall: bool,
        require_antivirus: bool,
    ) -> Self {
        DeviceComplianceChecker {
            min_os_version: min_os_version.to_string(),
            require_disk_encryption,
            require_secure_boot,
            require_firewall,
            require_antivirus,
        }
    }

    /// Evaluate device compliance against policy requirements
    pub fn evaluate(&self, device: &DeviceInfo) -> ComplianceStatus {
        let mut violations = Vec::new();

        // OS version check
        if self.is_version_less_than(&device.os_version, &self.min_os_version) {
            violations.push(format!(
                "OS version {} is below minimum {}",
                device.os_version, self.min_os_version
            ));
        }

        // Disk encryption check
        if self.require_disk_encryption && !device.disk_encrypted {
            violations.push("Disk encryption is not enabled".into());
        }

        // Secure boot check
        if self.require_secure_boot && !device.secure_boot_enabled {
            violations.push("Secure boot is not enabled".into());
        }

        // Firewall check
        if self.require_firewall && !device.firewall_enabled {
            violations.push("Firewall is not enabled".into());
        }

        // Antivirus check
        if self.require_antivirus && !device.antivirus_enabled {
            violations.push("Antivirus is not enabled".into());
        }

        // Staleness check (7 days)
        let now = chrono::Utc::now().timestamp();
        if now - device.last_health_check > 7 * 24 * 60 * 60 {
            violations.push("Device health check is stale (>7 days)".into());
        }

        if violations.is_empty() {
            ComplianceStatus::Compliant
        } else {
            ComplianceStatus::NonCompliant(violations)
        }
    }

    /// Simple semantic version comparison (major.minor.patch)
    fn is_version_less_than(&self, current: &str, minimum: &str) -> bool {
        let current_parts: Vec<u32> = current
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        let minimum_parts: Vec<u32> = minimum
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();

        for (c, m) in current_parts.iter().zip(minimum_parts.iter()) {
            if c < m {
                return true;
            }
            if c > m {
                return false;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliant_device() {
        let checker = DeviceComplianceChecker::new("10.0.19045", true, true, true, true);
        let device = DeviceInfo {
            device_id: "dev-001".into(),
            os_type: "Windows".into(),
            os_version: "10.0.19045".into(),
            disk_encrypted: true,
            secure_boot_enabled: true,
            firewall_enabled: true,
            antivirus_enabled: true,
            last_health_check: chrono::Utc::now().timestamp(),
        };

        assert_eq!(checker.evaluate(&device), ComplianceStatus::Compliant);
    }

    #[test]
    fn test_outdated_os() {
        let checker = DeviceComplianceChecker::new("10.0.19045", true, true, true, true);
        let device = DeviceInfo {
            device_id: "dev-002".into(),
            os_type: "Windows".into(),
            os_version: "10.0.17763".into(),
            disk_encrypted: true,
            secure_boot_enabled: true,
            firewall_enabled: true,
            antivirus_enabled: true,
            last_health_check: chrono::Utc::now().timestamp(),
        };

        assert!(matches!(checker.evaluate(&device), ComplianceStatus::NonCompliant(_)));
    }
}