//! Mesh traffic-capture planning (Layer 7).
//!
//! The proxy hot path never shells out to iptables or eBPF. This module builds
//! declarative plans that init containers / node agents can apply outside the
//! request path.

use std::net::IpAddr;

use tracing::warn;

use crate::config::conf_file::resolve_ferrum_var;

pub const DEFAULT_PROXY_UID: u32 = 1337;
const XTABLES_LOCK_WAIT_SECONDS: u8 = 5;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ip6TablesMode {
    Auto,
    Required,
    Disabled,
}

impl Ip6TablesMode {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "true" | "required" => Ok(Self::Required),
            "false" | "disabled" => Ok(Self::Disabled),
            other => Err(format!(
                "Invalid FERRUM_MESH_IP6TABLES_ENABLED '{other}'. Expected: auto, true, or false"
            )),
        }
    }

    pub fn as_env_value(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Required => "true",
            Self::Disabled => "false",
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
    /// TCP destination ports excluded from the inbound capture chain. Each
    /// listed port emits a `RETURN` rule placed BEFORE the inbound REDIRECT,
    /// so traffic to the port bypasses the mesh sidecar entirely.
    pub exclude_inbound_ports: Vec<u16>,
    pub ip6tables_mode: Ip6TablesMode,
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
            exclude_inbound_ports: Vec::new(),
            ip6tables_mode: Ip6TablesMode::Auto,
        }
    }

    pub fn from_env() -> Result<Self, String> {
        let mode = CaptureMode::parse(
            &resolve_ferrum_var("FERRUM_MESH_CAPTURE_MODE")
                .unwrap_or_else(|| "explicit".to_string()),
        )?;
        let proxy_uid = match resolve_ferrum_var("FERRUM_MESH_PROXY_UID") {
            Some(raw) => Some(parse_proxy_uid(&raw)?),
            None => Some(DEFAULT_PROXY_UID),
        };
        let include_cidrs = parse_cidr_env(
            &resolve_ferrum_var("FERRUM_MESH_CAPTURE_INCLUDE_CIDRS")
                .unwrap_or_else(|| "0.0.0.0/0".to_string()),
        );
        validate_cidr_list(&include_cidrs)?;
        let exclude_cidrs = parse_cidr_env(
            &resolve_ferrum_var("FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS").unwrap_or_default(),
        );
        if !exclude_cidrs.is_empty() {
            validate_cidr_list(&exclude_cidrs)?;
        }
        let exclude_ports = parse_port_list(
            &resolve_ferrum_var("FERRUM_MESH_CAPTURE_EXCLUDE_PORTS")
                .unwrap_or_else(|| "15001,15006,15008,15020".to_string()),
        )?;
        let exclude_inbound_ports = parse_port_list(
            &resolve_ferrum_var("FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS").unwrap_or_default(),
        )?;
        let ip6tables_mode = Ip6TablesMode::parse(
            &resolve_ferrum_var("FERRUM_MESH_IP6TABLES_ENABLED")
                .unwrap_or_else(|| "auto".to_string()),
        )?;
        Ok(Self {
            mode,
            proxy_uid,
            inbound_port: 15006,
            outbound_port: 15001,
            include_cidrs,
            exclude_cidrs,
            exclude_ports,
            exclude_inbound_ports,
            ip6tables_mode,
        })
    }
}

fn parse_cidr_env(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn parse_port_list(raw: &str) -> Result<Vec<u16>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let port = s
                .parse::<u16>()
                .map_err(|_| format!("Invalid port '{s}' in capture exclude ports"))?;
            if port == 0 {
                return Err(format!(
                    "Invalid port '{s}' in capture exclude ports: port must be 1-65535"
                ));
            }
            Ok(port)
        })
        .collect()
}

fn parse_proxy_uid(raw: &str) -> Result<u32, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(DEFAULT_PROXY_UID);
    }
    trimmed
        .parse::<u32>()
        .map_err(|_| format!("Invalid FERRUM_MESH_PROXY_UID '{raw}'. Expected unsigned integer"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IptablesPlan {
    pub v4_commands: Vec<String>,
    pub v6_commands: Vec<String>,
}

impl IptablesPlan {
    pub fn for_config(config: &CaptureConfig) -> Self {
        let v4_commands = commands_for_family("iptables", config, CidrFamily::V4, true);
        let v6_enabled = config.ip6tables_mode != Ip6TablesMode::Disabled;
        let v6_has_cidrs = config
            .include_cidrs
            .iter()
            .chain(config.exclude_cidrs.iter())
            .any(|cidr| cidr_family(cidr) == Some(CidrFamily::V6));
        let v6_commands = if v6_enabled && v6_has_cidrs {
            commands_for_family("ip6tables", config, CidrFamily::V6, false)
        } else {
            if !v6_enabled && v6_has_cidrs {
                warn!(
                    "Skipping IPv6 mesh capture rules because FERRUM_MESH_IP6TABLES_ENABLED=false"
                );
            }
            Vec::new()
        };

        Self {
            v4_commands,
            v6_commands,
        }
    }

    /// Generate iptables commands that reverse the setup performed by
    /// [`for_config`]. The cleanup order matters:
    ///
    /// 1. Delete the jump rules from the built-in chains (`PREROUTING`,
    ///    `OUTPUT`) so no new traffic enters the custom chains.
    /// 2. Flush the custom chains (remove all rules inside them).
    /// 3. Delete the now-empty custom chains.
    ///
    /// Each command uses `2>/dev/null || true` so partial cleanup (e.g.
    /// chains already removed by a previous run) does not fail the overall
    /// teardown.
    pub fn cleanup_commands() -> Vec<String> {
        cleanup_commands_for("iptables")
    }

    pub fn cleanup_v6_commands() -> Vec<String> {
        cleanup_commands_for("ip6tables")
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
        let fallback_cmds = self.fallback.script(Ip6TablesMode::Auto);
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

impl IptablesPlan {
    pub fn script(&self, ip6tables_mode: Ip6TablesMode) -> String {
        iptables_script(&self.v4_commands, &self.v6_commands, ip6tables_mode, true)
    }

    #[cfg(test)]
    pub fn cleanup_script(include_v6: bool, ip6tables_mode: Ip6TablesMode) -> String {
        let v4_commands = Self::cleanup_commands();
        let v6_commands = if include_v6 {
            Self::cleanup_v6_commands()
        } else {
            Vec::new()
        };
        iptables_script(&v4_commands, &v6_commands, ip6tables_mode, false)
    }
}

#[allow(dead_code)]
fn parse_kernel_requirement(version: &str) -> (u32, u32) {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(5);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(7);
    (major, minor)
}

pub fn should_fallback_to_iptables(kernel_release: &str) -> bool {
    let mut parts = kernel_release.split('.');
    let major = parts.next().and_then(|p| p.parse::<u32>().ok());
    let minor = parts.next().and_then(|p| p.parse::<u32>().ok());
    match (major, minor) {
        (Some(major), Some(minor)) => major < 5 || (major == 5 && minor < 7),
        _ => true,
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CidrFamily {
    V4,
    V6,
}

fn cidr_family(cidr: &str) -> Option<CidrFamily> {
    cidr.split_once('/')
        .and_then(|(addr, _)| addr.parse::<IpAddr>().ok())
        .map(|ip| {
            if ip.is_ipv4() {
                CidrFamily::V4
            } else {
                CidrFamily::V6
            }
        })
}

fn commands_for_family(
    binary: &str,
    config: &CaptureConfig,
    family: CidrFamily,
    always_emit: bool,
) -> Vec<String> {
    let include_cidrs: Vec<&str> = config
        .include_cidrs
        .iter()
        .filter(|cidr| cidr_family(cidr) == Some(family))
        .map(String::as_str)
        .collect();
    let exclude_cidrs: Vec<&str> = config
        .exclude_cidrs
        .iter()
        .filter(|cidr| cidr_family(cidr) == Some(family))
        .map(String::as_str)
        .collect();
    if !always_emit && include_cidrs.is_empty() && exclude_cidrs.is_empty() {
        return Vec::new();
    }

    let mut commands = Vec::new();
    commands.push(idempotent_new_chain(binary, "nat", "FERRUM_MESH_INBOUND"));
    commands.push(idempotent_new_chain(binary, "nat", "FERRUM_MESH_OUTBOUND"));

    for cidr in exclude_cidrs {
        commands.push(idempotent_append(
            binary,
            "nat",
            "FERRUM_MESH_OUTBOUND",
            &format!("-d {cidr} -j RETURN"),
        ));
    }
    for port in &config.exclude_ports {
        commands.push(idempotent_append(
            binary,
            "nat",
            "FERRUM_MESH_OUTBOUND",
            &format!("-p tcp --dport {port} -j RETURN"),
        ));
    }
    if let Some(uid) = config.proxy_uid {
        commands.push(idempotent_append(
            binary,
            "nat",
            "FERRUM_MESH_OUTBOUND",
            &format!("-m owner --uid-owner {uid} -j RETURN"),
        ));
    }
    for cidr in include_cidrs {
        commands.push(idempotent_append(
            binary,
            "nat",
            "FERRUM_MESH_OUTBOUND",
            &format!(
                "-p tcp -d {cidr} -j REDIRECT --to-ports {}",
                config.outbound_port
            ),
        ));
    }
    // Inbound port exclusions MUST be appended before the catch-all REDIRECT
    // below — once REDIRECT fires the chain returns, so any RETURN rule placed
    // after it would be silently bypassed.
    for port in &config.exclude_inbound_ports {
        commands.push(idempotent_append(
            binary,
            "nat",
            "FERRUM_MESH_INBOUND",
            &format!("-p tcp --dport {port} -j RETURN"),
        ));
    }
    commands.push(idempotent_append(
        binary,
        "nat",
        "FERRUM_MESH_INBOUND",
        &format!("-p tcp -j REDIRECT --to-ports {}", config.inbound_port),
    ));
    commands.push(idempotent_append(
        binary,
        "nat",
        "PREROUTING",
        "-p tcp -j FERRUM_MESH_INBOUND",
    ));
    commands.push(idempotent_append(
        binary,
        "nat",
        "OUTPUT",
        "-p tcp -j FERRUM_MESH_OUTBOUND",
    ));
    commands
}

fn iptables_script(
    v4_commands: &[String],
    v6_commands: &[String],
    ip6tables_mode: Ip6TablesMode,
    require_v6_preflight: bool,
) -> String {
    let mut chunks = Vec::new();
    if require_v6_preflight && !v6_commands.is_empty() && ip6tables_mode == Ip6TablesMode::Required
    {
        chunks.push(
            "command -v ip6tables >/dev/null 2>&1 || { echo \"ip6tables is required for IPv6 mesh capture\" >&2; exit 1; }\n\
             ip6tables -t nat -w 5 -L >/dev/null 2>&1 || { echo \"ip6tables nat table is required for IPv6 mesh capture\" >&2; exit 1; }"
                .to_string(),
        );
    }
    if !v4_commands.is_empty() {
        chunks.push(v4_commands.join("\n"));
    }
    if !v6_commands.is_empty() {
        let v6_script = v6_commands.join("\n");
        match ip6tables_mode {
            Ip6TablesMode::Auto => chunks.push(format!(
                "if command -v ip6tables >/dev/null 2>&1; then\n  if ip6tables -t nat -w 5 -L >/dev/null 2>&1; then\n{v6_script}\n  else\n    echo \"ip6tables nat table unavailable; skipping IPv6 mesh capture rules\"\n  fi\nelse\necho \"ip6tables not found; skipping IPv6 mesh capture rules\"\nfi"
            )),
            Ip6TablesMode::Required => chunks.push(v6_script),
            Ip6TablesMode::Disabled => {}
        }
    }
    chunks.join("\n")
}

fn cleanup_commands_for(binary: &str) -> Vec<String> {
    vec![
        // Step 1: remove jump rules from built-in chains
        idempotent_delete(binary, "nat", "OUTPUT", "-p tcp -j FERRUM_MESH_OUTBOUND"),
        idempotent_delete(binary, "nat", "PREROUTING", "-p tcp -j FERRUM_MESH_INBOUND"),
        // Step 2: flush custom chains
        flush_chain(binary, "nat", "FERRUM_MESH_INBOUND"),
        flush_chain(binary, "nat", "FERRUM_MESH_OUTBOUND"),
        // Step 3: delete custom chains (must be empty first)
        delete_chain(binary, "nat", "FERRUM_MESH_INBOUND"),
        delete_chain(binary, "nat", "FERRUM_MESH_OUTBOUND"),
    ]
}

fn idempotent_new_chain(binary: &str, table: &str, chain: &str) -> String {
    format!("{binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -N {chain} 2>/dev/null || true")
}

fn idempotent_append(binary: &str, table: &str, chain: &str, rule: &str) -> String {
    format!(
        "{binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -C {chain} {rule} 2>/dev/null || {binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -A {chain} {rule}"
    )
}

fn idempotent_delete(binary: &str, table: &str, chain: &str, rule: &str) -> String {
    format!(
        "{binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -D {chain} {rule} 2>/dev/null || true"
    )
}

fn flush_chain(binary: &str, table: &str, chain: &str) -> String {
    format!("{binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -F {chain} 2>/dev/null || true")
}

fn delete_chain(binary: &str, table: &str, chain: &str) -> String {
    format!("{binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -X {chain} 2>/dev/null || true")
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

        assert!(plan.v4_commands.iter().any(|cmd| cmd.contains("-C OUTPUT")));
        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("--uid-owner 1337"))
        );
        assert!(
            plan.v4_commands
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
                .v4_commands
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
                .v4_commands
                .iter()
                .any(|cmd| cmd.contains("--uid-owner 1337"))
        );
        assert!(
            plan.fallback
                .v4_commands
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

    #[test]
    fn cleanup_commands_reverses_setup() {
        let cleanup = IptablesPlan::cleanup_commands();

        // Must remove jumps from built-in chains first
        assert!(cleanup.iter().any(|cmd| cmd.contains("-D OUTPUT")));
        assert!(cleanup.iter().any(|cmd| cmd.contains("-D PREROUTING")));

        // Must flush then delete custom chains
        assert!(
            cleanup
                .iter()
                .any(|cmd| cmd.contains("-F FERRUM_MESH_INBOUND"))
        );
        assert!(
            cleanup
                .iter()
                .any(|cmd| cmd.contains("-F FERRUM_MESH_OUTBOUND"))
        );
        assert!(
            cleanup
                .iter()
                .any(|cmd| cmd.contains("-X FERRUM_MESH_INBOUND"))
        );
        assert!(
            cleanup
                .iter()
                .any(|cmd| cmd.contains("-X FERRUM_MESH_OUTBOUND"))
        );

        // Flush must come before delete (chain must be empty before removal)
        let flush_inbound_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-F FERRUM_MESH_INBOUND"))
            .unwrap();
        let delete_inbound_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-X FERRUM_MESH_INBOUND"))
            .unwrap();
        assert!(
            flush_inbound_pos < delete_inbound_pos,
            "flush must precede delete for FERRUM_MESH_INBOUND"
        );

        let flush_outbound_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-F FERRUM_MESH_OUTBOUND"))
            .unwrap();
        let delete_outbound_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-X FERRUM_MESH_OUTBOUND"))
            .unwrap();
        assert!(
            flush_outbound_pos < delete_outbound_pos,
            "flush must precede delete for FERRUM_MESH_OUTBOUND"
        );

        // Jump deletions must come before flush (no new traffic enters chains
        // while they are being torn down)
        let delete_output_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-D OUTPUT"))
            .unwrap();
        assert!(
            delete_output_pos < flush_outbound_pos,
            "OUTPUT jump delete must precede OUTBOUND flush"
        );
        let delete_prerouting_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-D PREROUTING"))
            .unwrap();
        assert!(
            delete_prerouting_pos < flush_inbound_pos,
            "PREROUTING jump delete must precede INBOUND flush"
        );
    }

    #[test]
    fn cleanup_commands_all_tolerate_missing_chains() {
        let cleanup = IptablesPlan::cleanup_commands();

        // Every cleanup command must have "|| true" so partial cleanup doesn't
        // fail the overall teardown
        for cmd in &cleanup {
            assert!(
                cmd.contains("|| true"),
                "cleanup command must tolerate missing chains: {cmd}"
            );
        }
    }

    #[test]
    fn iptables_plan_waits_for_xtables_lock() {
        let plan = IptablesPlan::for_config(&CaptureConfig::explicit(15006, 15001));

        for cmd in plan.v4_commands {
            assert!(
                cmd.contains(" -w 5 "),
                "iptables command should wait briefly for xtables lock: {cmd}"
            );
        }
    }

    #[test]
    fn setup_then_cleanup_covers_all_chains() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.proxy_uid = Some(DEFAULT_PROXY_UID);

        let setup = IptablesPlan::for_config(&config);
        let cleanup = IptablesPlan::cleanup_commands();

        // Every custom chain created in setup must be deleted in cleanup
        let setup_chains: Vec<&str> = setup
            .v4_commands
            .iter()
            .filter(|cmd| cmd.contains("-N "))
            .filter_map(|cmd| cmd.split("-N ").nth(1))
            .filter_map(|s| s.split_whitespace().next())
            .collect();

        for chain in &setup_chains {
            assert!(
                cleanup
                    .iter()
                    .any(|cmd| cmd.contains(&format!("-X {chain}"))),
                "chain {chain} created in setup but not deleted in cleanup"
            );
            assert!(
                cleanup
                    .iter()
                    .any(|cmd| cmd.contains(&format!("-F {chain}"))),
                "chain {chain} created in setup but not flushed in cleanup"
            );
        }

        // Every built-in chain jump in setup must have a corresponding delete in cleanup
        let setup_jumps: Vec<(&str, &str)> = setup
            .v4_commands
            .iter()
            .filter(|cmd| {
                (cmd.contains("-A PREROUTING") || cmd.contains("-C PREROUTING"))
                    || (cmd.contains("-A OUTPUT") || cmd.contains("-C OUTPUT"))
            })
            .filter_map(|cmd| {
                if cmd.contains("PREROUTING") {
                    Some(("PREROUTING", "FERRUM_MESH_INBOUND"))
                } else if cmd.contains("OUTPUT") {
                    Some(("OUTPUT", "FERRUM_MESH_OUTBOUND"))
                } else {
                    None
                }
            })
            .collect();

        for (chain, target) in &setup_jumps {
            assert!(
                cleanup
                    .iter()
                    .any(|cmd| cmd.contains(&format!("-D {chain}"))
                        && cmd.contains(&format!("-j {target}"))),
                "jump from {chain} to {target} in setup but no -D in cleanup"
            );
        }
    }

    #[test]
    fn parse_cidr_env_splits_and_trims() {
        let result = parse_cidr_env("10.0.0.0/8, 172.16.0.0/12 , 192.168.0.0/16");
        assert_eq!(
            result,
            vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
            ]
        );
    }

    #[test]
    fn parse_cidr_env_empty_string_returns_empty() {
        assert!(parse_cidr_env("").is_empty());
    }

    #[test]
    fn parse_port_list_valid() {
        let result = parse_port_list("15001, 15006, 15008 ,15020").unwrap();
        assert_eq!(result, vec![15001, 15006, 15008, 15020]);
    }

    #[test]
    fn parse_port_list_rejects_non_numeric() {
        assert!(parse_port_list("15001,abc").is_err());
    }

    #[test]
    fn parse_port_list_empty_string_returns_empty() {
        assert!(parse_port_list("").unwrap().is_empty());
    }

    #[test]
    fn parse_port_list_rejects_port_zero() {
        let err = parse_port_list("15001,0,15006").unwrap_err();
        assert!(err.contains("port must be 1-65535"), "actual: {err}");
    }

    #[test]
    fn parse_proxy_uid_rejects_invalid_env_value() {
        assert!(parse_proxy_uid("not-a-uid").is_err());
    }

    #[test]
    fn parse_proxy_uid_trims_valid_value() {
        assert_eq!(parse_proxy_uid(" 1338 ").unwrap(), 1338);
    }

    #[test]
    fn parse_proxy_uid_empty_uses_default() {
        assert_eq!(parse_proxy_uid("").unwrap(), DEFAULT_PROXY_UID);
    }

    #[test]
    fn iptables_plan_emits_inbound_exclude_return_rules_before_redirect() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.exclude_inbound_ports = vec![15090, 22];

        let plan = IptablesPlan::for_config(&config);

        for port in [15090, 22] {
            assert!(
                plan.v4_commands
                    .iter()
                    .any(|cmd| cmd.contains("FERRUM_MESH_INBOUND")
                        && cmd.contains(&format!("--dport {port} -j RETURN"))),
                "inbound RETURN rule missing for port {port}"
            );
        }

        // CRITICAL: every RETURN rule must precede the inbound REDIRECT,
        // otherwise the catch-all REDIRECT fires first and the exclusion is
        // silently bypassed.
        let redirect_pos = plan
            .v4_commands
            .iter()
            .position(|cmd| {
                cmd.contains("FERRUM_MESH_INBOUND")
                    && cmd.contains(&format!("REDIRECT --to-ports {}", config.inbound_port))
            })
            .expect("inbound REDIRECT command");
        for port in [15090, 22] {
            let return_pos = plan
                .v4_commands
                .iter()
                .position(|cmd| {
                    cmd.contains("FERRUM_MESH_INBOUND")
                        && cmd.contains(&format!("--dport {port} -j RETURN"))
                })
                .expect("inbound RETURN command");
            assert!(
                return_pos < redirect_pos,
                "inbound RETURN for port {port} must precede the REDIRECT"
            );
        }
    }

    #[test]
    fn iptables_plan_omits_inbound_returns_when_empty() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;

        let plan = IptablesPlan::for_config(&config);

        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|cmd| cmd.contains("FERRUM_MESH_INBOUND") && cmd.contains("-j RETURN")),
            "no inbound RETURN rules expected when exclude_inbound_ports is empty"
        );
    }

    #[test]
    fn iptables_plan_partitions_ipv4_and_ipv6_cidrs() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.exclude_cidrs = vec!["10.0.0.0/8".to_string(), "fd00::/8".to_string()];
        config.include_cidrs = vec!["172.16.0.0/12".to_string(), "2001:db8::/32".to_string()];

        let plan = IptablesPlan::for_config(&config);

        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("-d 10.0.0.0/8 -j RETURN")),
            "IPv4 exclude CIDR must still appear in the plan"
        );
        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("-d 172.16.0.0/12 -j REDIRECT --to-ports 15001")),
            "IPv4 include CIDR must still appear in the IPv4 plan"
        );
        assert!(
            !plan.v4_commands.iter().any(|cmd| cmd.contains("::/")),
            "IPv6 CIDRs must not appear in IPv4 commands: {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v6_commands
                .iter()
                .all(|cmd| cmd.starts_with("ip6tables ")),
            "IPv6 commands must use ip6tables: {:?}",
            plan.v6_commands
        );
        assert!(
            plan.v6_commands
                .iter()
                .any(|cmd| cmd.contains("-d fd00::/8 -j RETURN")),
            "IPv6 exclude CIDR must appear in the IPv6 plan"
        );
        assert!(
            plan.v6_commands
                .iter()
                .any(|cmd| cmd.contains("-d 2001:db8::/32 -j REDIRECT --to-ports 15001")),
            "IPv6 include CIDR must appear in the IPv6 plan"
        );
    }

    #[test]
    fn iptables_plan_v6_empty_when_ip6tables_disabled() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.ip6tables_mode = Ip6TablesMode::Disabled;
        config.include_cidrs = vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()];

        let plan = IptablesPlan::for_config(&config);

        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("-d 10.0.0.0/8 -j REDIRECT --to-ports 15001")),
            "IPv4 include CIDR must still appear in the plan"
        );
        assert!(
            plan.v6_commands.is_empty(),
            "disabled ip6tables mode must suppress IPv6 commands"
        );
    }

    #[test]
    fn iptables_plan_routes_ipv6_include_to_v6_commands_only() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["fd00::/8".to_string()];

        let plan = IptablesPlan::for_config(&config);

        assert!(
            !plan.v4_commands.iter().any(|cmd| {
                cmd.contains("FERRUM_MESH_OUTBOUND") && cmd.contains("REDIRECT --to-ports 15001")
            }),
            "no outbound REDIRECT should be emitted when the only include CIDR is IPv6"
        );
        assert!(
            plan.v6_commands.iter().any(|cmd| {
                cmd.contains("FERRUM_MESH_OUTBOUND")
                    && cmd.contains("-d fd00::/8 -j REDIRECT --to-ports 15001")
            }),
            "IPv6 outbound REDIRECT should be emitted through ip6tables"
        );
    }

    #[test]
    fn iptables_script_wraps_ipv6_commands_for_auto_probe() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["fd00::/8".to_string()];

        let script = IptablesPlan::for_config(&config).script(Ip6TablesMode::Auto);

        assert!(script.contains("command -v ip6tables"));
        assert!(script.contains("ip6tables -t nat -w 5 -L"));
        assert!(script.contains("ip6tables nat table unavailable"));
        assert!(script.contains("skipping IPv6 mesh capture rules"));
        assert!(script.contains("ip6tables -t nat"));
    }

    #[test]
    fn iptables_script_requires_ip6tables_when_configured_true() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.ip6tables_mode = Ip6TablesMode::Required;
        config.include_cidrs = vec!["fd00::/8".to_string()];

        let plan = IptablesPlan::for_config(&config);
        let script = plan.script(config.ip6tables_mode);

        assert!(script.contains("ip6tables is required for IPv6 mesh capture"));
        assert!(script.contains("ip6tables nat table is required for IPv6 mesh capture"));
        assert!(script.contains("ip6tables -t nat -w 5 -L"));
        assert!(script.contains("exit 1"));
        assert!(script.contains("ip6tables -t nat"));
        assert!(
            script
                .find("ip6tables is required for IPv6 mesh capture")
                .expect("ip6tables preflight")
                < script.find("iptables -t nat").expect("IPv4 setup"),
            "hard-required ip6tables preflight should run before IPv4 setup: {script}"
        );
    }

    #[test]
    fn cleanup_script_does_not_preflight_required_ip6tables() {
        let script = IptablesPlan::cleanup_script(true, Ip6TablesMode::Required);

        assert!(script.contains("iptables -t nat"));
        assert!(script.contains("ip6tables -t nat"));
        assert!(
            !script.contains("ip6tables is required for IPv6 mesh capture"),
            "cleanup must remain best-effort and avoid aborting v4 teardown when ip6tables is unavailable: {script}"
        );
        assert!(
            !script.contains("ip6tables -t nat -L"),
            "cleanup must not probe ip6tables nat availability before best-effort teardown: {script}"
        );
    }

    #[test]
    fn cidr_family_classifies_families() {
        assert_eq!(cidr_family("10.0.0.0/8"), Some(CidrFamily::V4));
        assert_eq!(cidr_family("0.0.0.0/0"), Some(CidrFamily::V4));
        assert_eq!(cidr_family("127.0.0.0/8"), Some(CidrFamily::V4));
        assert_eq!(cidr_family("fd00::/8"), Some(CidrFamily::V6));
        assert_eq!(cidr_family("2001:db8::/32"), Some(CidrFamily::V6));
        assert_eq!(cidr_family("::/0"), Some(CidrFamily::V6));
        // Malformed shapes are not IPv4; admission validator catches these earlier.
        assert_eq!(cidr_family("not-a-cidr"), None);
        assert_eq!(cidr_family("10.0.0.0"), None);
    }

    #[test]
    fn ip6tables_mode_parse_accepts_documented_values() {
        assert_eq!(Ip6TablesMode::parse("auto").unwrap(), Ip6TablesMode::Auto);
        assert_eq!(
            Ip6TablesMode::parse("true").unwrap(),
            Ip6TablesMode::Required
        );
        assert_eq!(
            Ip6TablesMode::parse("required").unwrap(),
            Ip6TablesMode::Required
        );
        assert_eq!(
            Ip6TablesMode::parse("false").unwrap(),
            Ip6TablesMode::Disabled
        );
        assert!(Ip6TablesMode::parse("sometimes").is_err());
    }

    // Serialize env-driven tests in this module so parallel cargo test runs do
    // not race on the same `FERRUM_MESH_CAPTURE_*` vars consumed by `from_env`.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_capture_env<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let keys = [
            "FERRUM_MESH_CAPTURE_MODE",
            "FERRUM_MESH_PROXY_UID",
            "FERRUM_MESH_CAPTURE_INCLUDE_CIDRS",
            "FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS",
            "FERRUM_MESH_CAPTURE_EXCLUDE_PORTS",
            "FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS",
            "FERRUM_MESH_IP6TABLES_ENABLED",
        ];
        for key in keys {
            // SAFETY: test-only env mutation, serialized by ENV_LOCK above.
            unsafe { std::env::remove_var(key) };
        }
        for (key, value) in vars {
            // SAFETY: test-only env mutation, serialized by ENV_LOCK above.
            unsafe { std::env::set_var(key, value) };
        }
        f();
        for key in keys {
            // SAFETY: test-only env mutation, serialized by ENV_LOCK above.
            unsafe { std::env::remove_var(key) };
        }
    }

    #[test]
    fn from_env_parses_exclude_inbound_ports() {
        with_capture_env(
            &[("FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS", "15090, 22")],
            || {
                let config = CaptureConfig::from_env().expect("config");
                assert_eq!(config.exclude_inbound_ports, vec![15090, 22]);
            },
        );
    }

    #[test]
    fn from_env_defaults_exclude_inbound_ports_to_empty() {
        with_capture_env(&[], || {
            let config = CaptureConfig::from_env().expect("config");
            assert!(config.exclude_inbound_ports.is_empty());
            assert_eq!(config.ip6tables_mode, Ip6TablesMode::Auto);
        });
    }

    #[test]
    fn from_env_rejects_invalid_exclude_inbound_ports() {
        with_capture_env(
            &[("FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS", "not-a-port")],
            || {
                let result = CaptureConfig::from_env();
                assert!(result.is_err());
            },
        );
    }

    #[test]
    fn from_env_parses_ip6tables_mode() {
        with_capture_env(&[("FERRUM_MESH_IP6TABLES_ENABLED", "true")], || {
            let config = CaptureConfig::from_env().expect("config");
            assert_eq!(config.ip6tables_mode, Ip6TablesMode::Required);
        });
    }

    #[test]
    fn from_env_rejects_invalid_ip6tables_mode() {
        with_capture_env(&[("FERRUM_MESH_IP6TABLES_ENABLED", "maybe")], || {
            let result = CaptureConfig::from_env();
            assert!(result.is_err());
        });
    }
}
