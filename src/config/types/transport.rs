//! Transport-related configuration types.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::address::{NetLocation, NetLocationPortRange};
use crate::option_util::{NoneOrOne, NoneOrSome};

use super::common::default_true;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BindLocation {
    Address(NetLocationPortRange),
    Path(PathBuf),
}

impl std::fmt::Display for BindLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindLocation::Address(n) => write!(f, "{n}"),
            BindLocation::Path(p) => write!(f, "{}", p.display()),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Tcp,
    Quic,
    Udp,
}

impl Transport {
    /// Returns true if this is the default transport (TCP)
    pub fn is_default(&self) -> bool {
        matches!(self, Transport::Tcp)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TcpConfig {
    #[serde(default = "default_true")]
    pub no_delay: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        TcpConfig { no_delay: true }
    }
}

/// Congestion control algorithm for QUIC-based protocols.
///
/// NOTE: This enum intentionally does NOT use `#[serde(tag = "type")]` (internally tagged).
/// There is a known bug in serde_yaml 0.9.x where internally tagged enums fail to deserialize
/// when the same struct also contains `untagged` enum fields (like `NoneOrSome`), producing:
/// "invalid type: map, expected a Value::Tagged enum".
/// See: https://github.com/dtolnay/serde-yaml/issues/415
///
/// Instead, we accept both a plain string ("default" / "brutal") and a map format.
#[derive(Debug, Clone, Default)]
pub enum CongestionControl {
    /// Default Quinn congestion controller (Cubic).
    #[default]
    Default,
    /// Brutal - bandwidth-hint-driven congestion controller.
    /// Uses BDP-based window calculation instead of traditional loss-based AIMD.
    /// Particularly effective in high-loss network environments.
    Brutal(BrutalCongestionConfig),
}

impl serde::Serialize for CongestionControl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            CongestionControl::Default => serializer.serialize_str("default"),
            CongestionControl::Brutal(config) => {
                // Serialize as a map with type + config fields
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("type", "brutal")?;
                map.serialize_entry("bandwidth", &config.bandwidth)?;
                map.serialize_entry("cwnd_gain", &config.cwnd_gain)?;
                map.serialize_entry("min_window", &config.min_window)?;
                map.serialize_entry("ack_compensate", &config.ack_compensate)?;
                map.end()
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for CongestionControl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Error, Visitor};

        struct CongestionControlVisitor;

        impl<'de> Visitor<'de> for CongestionControlVisitor {
            type Value = CongestionControl;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string (\"default\" or \"brutal\") or a map with congestion control config")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                match value.to_lowercase().as_str() {
                    "default" => Ok(CongestionControl::Default),
                    "brutal" => Ok(CongestionControl::Brutal(BrutalCongestionConfig::default())),
                    other => Err(E::custom(format!(
                        "unknown congestion control type: \"{other}\". Expected \"default\" or \"brutal\""
                    ))),
                }
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                // Check if this is a tagged format: {type: "brutal", ...}
                // or an inline format: {bandwidth: "100m", ...}
                let mut cc_type: Option<String> = None;
                let mut bandwidth: Option<String> = None;
                let mut cwnd_gain: Option<f64> = None;
                let mut min_window: Option<u64> = None;
                let mut ack_compensate: Option<bool> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => {
                            cc_type = Some(map.next_value()?);
                        }
                        "bandwidth" => {
                            bandwidth = Some(map.next_value()?);
                        }
                        "cwnd_gain" => {
                            cwnd_gain = Some(map.next_value()?);
                        }
                        "min_window" => {
                            min_window = Some(map.next_value()?);
                        }
                        "ack_compensate" => {
                            ack_compensate = Some(map.next_value()?);
                        }
                        other => {
                            // Ignore unknown fields
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                            log::warn!("unknown congestion control field: {other}, ignoring");
                        }
                    }
                }

                let is_brutal = cc_type
                    .as_deref()
                    .map(|t| t.to_lowercase() == "brutal")
                    .unwrap_or(false);

                // If type is explicitly "default", return Default regardless of other fields
                if cc_type
                    .as_deref()
                    .map(|t| t.to_lowercase() == "default")
                    .unwrap_or(false)
                {
                    return Ok(CongestionControl::Default);
                }

                // If type is "brutal" or any brutal-specific field is present, use Brutal
                if is_brutal
                    || bandwidth.is_some()
                    || cwnd_gain.is_some()
                    || min_window.is_some()
                    || ack_compensate.is_some()
                {
                    Ok(CongestionControl::Brutal(BrutalCongestionConfig {
                        bandwidth: bandwidth.unwrap_or_else(default_brutal_bandwidth),
                        cwnd_gain: cwnd_gain.unwrap_or_else(default_brutal_cwnd_gain),
                        min_window: min_window.unwrap_or_else(default_brutal_min_window),
                        ack_compensate: ack_compensate.unwrap_or(false),
                    }))
                } else if cc_type.is_none() {
                    // No type field and no brutal fields — treat as Default
                    Ok(CongestionControl::Default)
                } else {
                    Err(A::Error::custom(format!(
                        "unknown congestion control type: {:?}",
                        cc_type
                    )))
                }
            }
        }

        deserializer.deserialize_any(CongestionControlVisitor)
    }
}

impl PartialEq for CongestionControl {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (CongestionControl::Default, CongestionControl::Default) => true,
            (CongestionControl::Brutal(a), CongestionControl::Brutal(b)) => a == b,
            _ => false,
        }
    }
}

/// Configuration for the Brutal congestion controller.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct BrutalCongestionConfig {
    /// Target bandwidth in human-readable format (e.g., "100m", "1.5g", "30k").
    /// Default: "1m" (1 Mbps)
    #[serde(default = "default_brutal_bandwidth")]
    pub bandwidth: String,
    /// Multiplier applied to BDP when calculating cwnd.
    /// Higher values are more aggressive but may exceed configured bandwidth.
    /// Default: 1.25
    #[serde(default = "default_brutal_cwnd_gain")]
    pub cwnd_gain: f64,
    /// Minimum congestion window in bytes.
    /// Default: 16384 (16 KB)
    #[serde(default = "default_brutal_min_window")]
    pub min_window: u64,
    /// Enable ACK rate compensation. When enabled, cwnd is divided by the ACK rate
    /// to compensate for packet loss. This can cause bursty behavior.
    /// Default: false
    #[serde(default)]
    pub ack_compensate: bool,
}

fn default_brutal_bandwidth() -> String {
    "1m".to_string()
}

fn default_brutal_cwnd_gain() -> f64 {
    1.25
}

fn default_brutal_min_window() -> u64 {
    16 * 1024
}

impl Default for BrutalCongestionConfig {
    fn default() -> Self {
        Self {
            bandwidth: default_brutal_bandwidth(),
            cwnd_gain: default_brutal_cwnd_gain(),
            min_window: default_brutal_min_window(),
            ack_compensate: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_congestion_control_default_string() {
        // String format: "default"
        let cc: CongestionControl = serde_yaml::from_str("default").unwrap();
        assert!(matches!(cc, CongestionControl::Default));
    }

    #[test]
    fn test_congestion_control_brutal_string() {
        // String format: "brutal" (uses defaults)
        let cc: CongestionControl = serde_yaml::from_str("brutal").unwrap();
        match cc {
            CongestionControl::Brutal(config) => {
                assert_eq!(config.bandwidth, "1m");
                assert_eq!(config.cwnd_gain, 1.25);
            }
            _ => panic!("expected Brutal variant"),
        }
    }

    #[test]
    fn test_congestion_control_brutal_map_with_type() {
        // Tagged map format: {type: brutal, bandwidth: 100m}
        let yaml = r#"
type: brutal
bandwidth: 100m
"#;
        let cc: CongestionControl = serde_yaml::from_str(yaml).unwrap();
        match cc {
            CongestionControl::Brutal(config) => {
                assert_eq!(config.bandwidth, "100m");
            }
            _ => panic!("expected Brutal variant"),
        }
    }

    #[test]
    fn test_congestion_control_brutal_map_inline() {
        // Inline map format without type: {bandwidth: 100m, cwnd_gain: 1.5}
        let yaml = r#"
bandwidth: 100m
cwnd_gain: 1.5
"#;
        let cc: CongestionControl = serde_yaml::from_str(yaml).unwrap();
        match cc {
            CongestionControl::Brutal(config) => {
                assert_eq!(config.bandwidth, "100m");
                assert!((config.cwnd_gain - 1.5).abs() < 0.001);
            }
            _ => panic!("expected Brutal variant"),
        }
    }

    #[test]
    fn test_congestion_control_serde_roundtrip() {
        // Test Default variant serialization
        let cc_default = CongestionControl::Default;
        let yaml_default = serde_yaml::to_string(&cc_default).unwrap();
        println!("Default variant YAML: {yaml_default}");
        assert_eq!(yaml_default.trim(), "\"default\"");
        let back_default: CongestionControl = serde_yaml::from_str(&yaml_default).unwrap();
        assert!(matches!(back_default, CongestionControl::Default));

        // Test Brutal variant serialization
        let cc_brutal = CongestionControl::Brutal(BrutalCongestionConfig {
            bandwidth: "100m".to_string(),
            cwnd_gain: 1.5,
            min_window: 32768,
            ack_compensate: true,
        });
        let yaml_brutal = serde_yaml::to_string(&cc_brutal).unwrap();
        println!("Brutal variant YAML:\n{yaml_brutal}");
        let back_brutal: CongestionControl = serde_yaml::from_str(&yaml_brutal).unwrap();
        assert!(matches!(back_brutal, CongestionControl::Brutal(_)));
    }

    #[test]
    fn test_server_quic_config_with_brutal() {
        let config = ServerQuicConfig {
            cert: "test.crt".to_string(),
            key: "test.key".to_string(),
            alpn_protocols: NoneOrSome::One("hysteria".to_string()),
            client_ca_certs: NoneOrSome::None,
            client_fingerprints: NoneOrSome::None,
            num_endpoints: 1,
            congestion_control: CongestionControl::Brutal(BrutalCongestionConfig {
                bandwidth: "100m".to_string(),
                ..Default::default()
            }),
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        println!("ServerQuicConfig YAML:\n{yaml}");
        let back: ServerQuicConfig = serde_yaml::from_str(&yaml).unwrap();
        assert!(matches!(back.congestion_control, CongestionControl::Brutal(_)));
    }

    #[test]
    fn test_server_quic_config_from_yaml() {
        // Simulate what the user would write in their config file
        let yaml = r#"
cert: server.crt
key: server.key
alpn_protocols: hysteria
congestion_control:
  type: brutal
  bandwidth: 100m
"#;
        let config: ServerQuicConfig = serde_yaml::from_str(yaml).unwrap();
        match config.congestion_control {
            CongestionControl::Brutal(cfg) => {
                assert_eq!(cfg.bandwidth, "100m");
                assert_eq!(cfg.cwnd_gain, 1.25); // default
            }
            _ => panic!("expected Brutal congestion control"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerQuicConfig {
    pub cert: String,
    pub key: String,
    #[serde(alias = "alpn_protocol", default)]
    pub alpn_protocols: NoneOrSome<String>,
    #[serde(alias = "client_ca_cert", default)]
    pub client_ca_certs: NoneOrSome<String>,
    #[serde(alias = "client_fingerprint", default)]
    pub client_fingerprints: NoneOrSome<String>,
    // num_endpoints of 0 will use the number of threads as the default value.
    #[serde(default)]
    pub num_endpoints: usize,
    /// Congestion control algorithm. Only used by QUIC-based protocols
    /// (Hysteria2, TUIC v5).
    /// Default: "default" (Quinn's built-in Cubic).
    #[serde(default)]
    pub congestion_control: CongestionControl,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientQuicConfig {
    #[serde(default = "default_true")]
    pub verify: bool,
    #[serde(alias = "server_fingerprint", default)]
    pub server_fingerprints: NoneOrSome<String>,
    #[serde(default)]
    pub sni_hostname: NoneOrOne<String>,
    #[serde(alias = "alpn_protocol", default)]
    pub alpn_protocols: NoneOrSome<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,
}

impl Default for ClientQuicConfig {
    fn default() -> Self {
        Self {
            verify: true,
            server_fingerprints: NoneOrSome::Unspecified,
            sni_hostname: NoneOrOne::Unspecified,
            alpn_protocols: NoneOrSome::Unspecified,
            key: None,
            cert: None,
        }
    }
}

impl From<NetLocation> for BindLocation {
    fn from(loc: NetLocation) -> Self {
        BindLocation::Address(loc.into())
    }
}
