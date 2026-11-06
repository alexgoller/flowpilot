//! Which gateway host Integrations mode connects to. The host is not in the source: a build can embed
//! one through the `FLOWPILOT_BUILD_GATEWAY` (and `FLOWPILOT_BUILD_GATEWAY_STAGING_DOMAIN`)
//! environment variable at compile time, and `pce_kafka.gateway` overrides it at run time.

use crate::config::PceKafka;

/// An `option_env!` value, with an empty one treated as unset.
const fn non_empty(v: Option<&'static str>) -> Option<&'static str> {
    match v {
        Some(s) if !s.is_empty() => Some(s),
        _ => None,
    }
}

/// The gateway host compiled into this build, if any.
pub const BUILTIN_GATEWAY: Option<&str> = non_empty(option_env!("FLOWPILOT_BUILD_GATEWAY"));
/// The domain `env_override` (`dev` or `stage`) is resolved under, if this build has one.
pub const BUILTIN_STAGING_DOMAIN: Option<&str> =
    non_empty(option_env!("FLOWPILOT_BUILD_GATEWAY_STAGING_DOMAIN"));

pub const NO_GATEWAY: &str = "this build has no built-in Integrations gateway; set pce_kafka.gateway";

/// The gateway to connect to: `pce_kafka.gateway` when set (it wins over `env_override`), else the
/// built-in one, or `<env_override>-<staging domain>` for `env_override` `dev` or `stage`, as in FlowLink.
pub fn gateway_host(k: &PceKafka) -> Result<String, String> {
    gateway_host_with(k, BUILTIN_GATEWAY, BUILTIN_STAGING_DOMAIN)
}

pub(crate) fn gateway_host_with(
    k: &PceKafka,
    builtin: Option<&str>,
    staging_domain: Option<&str>,
) -> Result<String, String> {
    if !k.gateway.is_empty() {
        return Ok(k.gateway.clone());
    }
    // Divergence: a built-in production gateway is required even when env_override is set (FlowLink
    // needs none there); release builds set both.
    let builtin = builtin.ok_or_else(|| NO_GATEWAY.to_string())?;
    match (k.env_override.as_str(), staging_domain) {
        ("", _) => Ok(builtin.to_string()),
        (env, Some(domain)) => Ok(format!("{env}-{domain}")),
        _ => Err(NO_GATEWAY.to_string()),
    }
}

/// The `-version` line telling whether this build can reach an Integrations gateway without `pce_kafka.gateway`.
pub fn version_line() -> String {
    format!("Built-in Integrations gateway: {}", if BUILTIN_GATEWAY.is_some() { "yes" } else { "no" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_override_default_and_staging() {
        let k = |o: &str, g: &str| PceKafka {
            installation_id: "i".into(),
            env_override: o.into(),
            gateway: g.into(),
            ..Default::default()
        };
        assert_eq!(gateway_host_with(&k("", "mock:8444"), Some("gw.example.test"), None).unwrap(), "mock:8444");
        assert_eq!(gateway_host_with(&k("dev", "mock:8444"), None, None).unwrap(), "mock:8444"); // override wins over env_override
        assert_eq!(gateway_host_with(&k("", ""), Some("gw.example.test"), None).unwrap(), "gw.example.test");
        assert_eq!(
            gateway_host_with(&k("stage", ""), Some("gw.example.test"), Some("staging.example.test")).unwrap(),
            "stage-staging.example.test"
        );
        assert_eq!(gateway_host_with(&k("", ""), None, Some("staging.example.test")).unwrap_err(), NO_GATEWAY);
        assert_eq!(
            gateway_host_with(&k("dev", ""), Some("gw.example.test"), Some("staging.example.test")).unwrap(),
            "dev-staging.example.test"
        );
        assert_eq!(gateway_host_with(&k("dev", ""), Some("gw.example.test"), None).unwrap_err(), NO_GATEWAY);
    }

    #[test]
    fn version_line_follows_the_built_in_gateway() {
        let yes = if BUILTIN_GATEWAY.is_some() { "yes" } else { "no" };
        assert_eq!(version_line(), format!("Built-in Integrations gateway: {yes}"));
    }
}
