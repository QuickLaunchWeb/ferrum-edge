//! Mesh traffic-capture planning (Layer 7).
//!
//! The proxy hot path never shells out to iptables or eBPF. This module builds
//! declarative plans that init containers / node agents can apply outside the
//! request path.

use std::net::IpAddr;

pub const DEFAULT_PROXY_UID: u32 = 1337;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    Explicit,
    Iptables,
    Ebpf,
}

impl CaptureMode {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_ascii_lowercase().as_str() {
            "explicit" => Ok(Self::Explicit),
            "iptables" => Ok(Self::Iptables),
            "ebpf" => Ok(Self::Ebpf),
            other => Err(format!(
                "Invalid FERRUM_MESH_CAPTURE_MODE '{other}'. Expected: explicit, iptables, or ebpf"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    pub mode: CaptureMode,
    pub proxy_uid: Option<u32>,
    pub inbound_port: u16,
    pub outbound_port: u16,
    pub include_cidrs: Vec<String>,
    pub exclude_cidrs: Vec<String>,
    pub exclude_ports: Vec<u16>,
}

impl CaptureConfig {
    pub fn explicit(inbound_port: u16, outbound_port: u16) -> Self {
        Self {
            mode: CaptureMode::Explicit,
            proxy_uid: Some(DEFAULT_PROXY_UID),
            inbound_port,
            outbound_port,
            include_cidrs: vec!["0.0.0.0/0".to_string()],
            exclude_cidrs: Vec::new(),
            exclude_ports: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IptablesPlan {
    pub commands: Vec<String>,
}

impl IptablesPlan {
    pub fn for_config(config: &CaptureConfig) -> Self {
        let mut commands = Vec::new();
        commands.push(idempotent_new_chain("nat", "FERRUM_MESH_INBOUND"));
        commands.push(idempotent_new_chain("nat", "FERRUM_MESH_OUTBOUND"));

        for cidr in &config.exclude_cidrs {
            commands.push(idempotent_append(
                "nat",
                "FERRUM_MESH_OUTBOUND",
                &format!("-d {cidr} -j RETURN"),
            ));
        }
        for port in &config.exclude_ports {
            commands.push(idempotent_append(
                "nat",
                "FERRUM_MESH_OUTBOUND",
                &format!("-p tcp --dport {port} -j RETURN"),
            ));
        }
        if let Some(uid) = config.proxy_uid {
            commands.push(idempotent_append(
                "nat",
                "FERRUM_MESH_OUTBOUND",
                &format!("-m owner --uid-owner {uid} -j RETURN"),
            ));
        }
        for cidr in &config.include_cidrs {
            commands.push(idempotent_append(
                "nat",
                "FERRUM_MESH_OUTBOUND",
                &format!(
                    "-p tcp -d {cidr} -j REDIRECT --to-ports {}",
                    config.outbound_port
                ),
            ));
        }
        commands.push(idempotent_append(
            "nat",
            "FERRUM_MESH_INBOUND",
            &format!("-p tcp -j REDIRECT --to-ports {}", config.inbound_port),
        ));
        commands.push(idempotent_append(
            "nat",
            "PREROUTING",
            "-p tcp -j FERRUM_MESH_INBOUND",
        ));
        commands.push(idempotent_append(
            "nat",
            "OUTPUT",
            "-p tcp -j FERRUM_MESH_OUTBOUND",
        ));

        Self { commands }
    }
}

// EbpfPlan and helpers are consumed by the node-agent eBPF capture path
// (ambient DaemonSet integration). The sidecar injector deliberately does NOT
// inject an init container for eBPF mode — privileged capabilities would cause
// Pod Security Baseline/Restricted admission rejection on every pod, even when
// the script does nothing on 5.7+ kernels.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfPlan {
    pub enabled: bool,
    pub fallback: IptablesPlan,
    pub required_kernel: &'static str,
}

#[allow(dead_code)]
impl EbpfPlan {
    pub fn for_config(config: &CaptureConfig) -> Self {
        Self {
            enabled: config.mode == CaptureMode::Ebpf,
            fallback: IptablesPlan::for_config(config),
            required_kernel: "5.7",
        }
    }

    pub fn fallback_script(&self) -> String {
        let fallback_cmds = self.fallback.commands.join("\n");
        let (major, minor) = parse_kernel_requirement(self.required_kernel);
        format!(
            "MAJOR=$(uname -r | cut -d. -f1)\n\
             MINOR=$(uname -r | cut -d. -f2)\n\
             if [ \"$MAJOR\" -lt {major} ] || \
             {{ [ \"$MAJOR\" -eq {major} ] && [ \"$MINOR\" -lt {minor} ]; }}; then\n\
             echo \"Kernel $(uname -r) < {req}, falling back to iptables\"\n\
             {fallback_cmds}\n\
             else\n\
             echo \"Kernel $(uname -r) supports eBPF capture, skipping iptables\"\n\
             fi",
            req = self.required_kernel,
        )
    }
}

#[allow(dead_code)]
fn parse_kernel_requirement(version: &str) -> (u32, u32) {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(5);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(7);
    (major, minor)
}

// Used by the eBPF node-agent path once it is wired to runtime kernel probing.
#[allow(dead_code)]
pub fn should_fallback_to_iptables(kernel_release: &str) -> bool {
    let mut parts = kernel_release.split('.');
    let major = parts.next().and_then(|p| p.parse::<u32>().ok());
    let minor = parts.next().and_then(|p| p.parse::<u32>().ok());
    match (major, minor) {
        (Some(major), Some(minor)) => major < 5 || (major == 5 && minor < 7),
        _ => true,
    }
}

// Validates operator-provided include/exclude CIDRs before emitting capture
// rules; the env-facing CIDR knobs land with the node-agent integration.
#[allow(dead_code)]
pub fn validate_cidr_list(cidrs: &[String]) -> Result<(), String> {
    for cidr in cidrs {
        let Some((addr, prefix)) = cidr.split_once('/') else {
            return Err(format!("CIDR '{cidr}' must include a prefix length"));
        };
        let ip: IpAddr = addr
            .parse()
            .map_err(|_| format!("CIDR '{cidr}' has invalid IP address"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| format!("CIDR '{cidr}' has invalid prefix length"))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!(
                "CIDR '{cidr}' prefix length {prefix} exceeds max {max}"
            ));
        }
    }
    Ok(())
}

fn idempotent_new_chain(table: &str, chain: &str) -> String {
    format!("iptables -t {table} -N {chain} 2>/dev/null || true")
}

fn idempotent_append(table: &str, chain: &str, rule: &str) -> String {
    format!(
        "iptables -t {table} -C {chain} {rule} 2>/dev/null || iptables -t {table} -A {chain} {rule}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iptables_plan_is_idempotent() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.proxy_uid = Some(DEFAULT_PROXY_UID);
        config.exclude_cidrs.push("10.0.0.0/8".to_string());
        config.exclude_ports.push(15020);

        let plan = IptablesPlan::for_config(&config);

        assert!(plan.commands.iter().any(|cmd| cmd.contains("-C OUTPUT")));
        assert!(
            plan.commands
                .iter()
                .any(|cmd| cmd.contains("--uid-owner 1337"))
        );
        assert!(
            plan.commands
                .iter()
                .any(|cmd| cmd.contains("--to-ports 15001"))
        );
    }

    #[test]
    fn explicit_capture_defaults_to_proxy_uid_exclusion() {
        let config = CaptureConfig::explicit(15006, 15001);

        assert_eq!(config.proxy_uid, Some(DEFAULT_PROXY_UID));
        assert!(
            IptablesPlan::for_config(&config)
                .commands
                .iter()
                .any(|cmd| cmd.contains("--uid-owner 1337"))
        );
    }

    #[test]
    fn ebpf_falls_back_on_old_kernel() {
        assert!(should_fallback_to_iptables("5.4.0"));
        assert!(!should_fallback_to_iptables("5.7.0"));
        assert!(!should_fallback_to_iptables("6.6.12"));
    }

    #[test]
    fn ebpf_plan_carries_iptables_fallback() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Ebpf;

        let plan = EbpfPlan::for_config(&config);

        assert!(plan.enabled);
        assert_eq!(plan.required_kernel, "5.7");
        assert!(
            plan.fallback
                .commands
                .iter()
                .any(|cmd| cmd.contains("--uid-owner 1337"))
        );
        assert!(
            plan.fallback
                .commands
                .iter()
                .any(|cmd| cmd.contains("--to-ports 15001"))
        );
    }

    #[test]
    fn ebpf_fallback_script_contains_kernel_check_and_iptables() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Ebpf;

        let plan = EbpfPlan::for_config(&config);
        let script = plan.fallback_script();

        assert!(script.contains("uname -r"));
        assert!(script.contains("-lt 5"));
        assert!(script.contains("-lt 7"));
        assert!(script.contains("falling back to iptables"));
        assert!(script.contains("supports eBPF"));
        assert!(script.contains("--to-ports 15001"));
        assert!(script.contains("--to-ports 15006"));
    }

    #[test]
    fn cidr_validation_checks_prefix_range() {
        assert!(validate_cidr_list(&["10.0.0.0/8".to_string()]).is_ok());
        assert!(validate_cidr_list(&["10.0.0.0/64".to_string()]).is_err());
    }
}
