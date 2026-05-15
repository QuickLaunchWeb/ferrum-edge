//! Mesh traffic-capture planning (Layer 7).
//!
//! The proxy hot path never shells out to iptables or eBPF. This module builds
//! declarative plans that init containers / node agents can apply outside the
//! request path.

use std::net::IpAddr;

use tracing::warn;

use crate::config::conf_file::resolve_ferrum_var;

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
    pub include_outbound_ports: Vec<u16>,
    pub exclude_cidrs: Vec<String>,
    pub exclude_ports: Vec<u16>,
    /// TCP destination ports excluded from the inbound capture chain. Each
    /// listed port emits a `RETURN` rule placed BEFORE the inbound REDIRECT,
    /// so traffic to the port bypasses the mesh sidecar entirely.
    pub exclude_inbound_ports: Vec<u16>,
}

impl CaptureConfig {
    pub fn explicit(inbound_port: u16, outbound_port: u16) -> Self {
        Self {
            mode: CaptureMode::Explicit,
            proxy_uid: Some(DEFAULT_PROXY_UID),
            inbound_port,
            outbound_port,
            include_cidrs: vec!["0.0.0.0/0".to_string()],
            include_outbound_ports: Vec::new(),
            exclude_cidrs: Vec::new(),
            exclude_ports: Vec::new(),
            exclude_inbound_ports: Vec::new(),
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
        Ok(Self {
            mode,
            proxy_uid,
            inbound_port: 15006,
            outbound_port: 15001,
            include_cidrs,
            include_outbound_ports: Vec::new(),
            exclude_cidrs,
            exclude_ports,
            exclude_inbound_ports,
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
    pub commands: Vec<String>,
}

impl IptablesPlan {
    pub fn for_config(config: &CaptureConfig) -> Self {
        let mut commands = Vec::new();
        commands.push(idempotent_new_chain("nat", "FERRUM_MESH_INBOUND"));
        commands.push(idempotent_new_chain("nat", "FERRUM_MESH_OUTBOUND"));

        // IPv6 CIDRs are skipped because the init container only invokes the
        // IPv4 `iptables` binary — feeding a literal `-d fd00::/8` would make
        // the rule append fail at runtime, leaving the capture chain partially
        // populated (rules already appended stay, later rules never fire). A
        // future change can fan these out to `ip6tables`. Until then, dropping
        // them with a warning is safer than emitting a broken plan.
        for cidr in &config.exclude_cidrs {
            if !is_ipv4_cidr(cidr) {
                warn!(
                    cidr = %cidr,
                    "Skipping non-IPv4 CIDR in outbound exclude list (ip6tables fan-out not yet implemented)"
                );
                continue;
            }
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
        let include_cidrs: Vec<&String> = config
            .include_cidrs
            .iter()
            .filter(|cidr| {
                if !is_ipv4_cidr(cidr) {
                    warn!(
                        cidr = %cidr,
                        "Skipping non-IPv4 CIDR in outbound include list (ip6tables fan-out not yet implemented)"
                    );
                    return false;
                }
                true
            })
            .collect();
        if config.include_outbound_ports.is_empty() {
            for cidr in include_cidrs {
                commands.push(idempotent_append(
                    "nat",
                    "FERRUM_MESH_OUTBOUND",
                    &format!(
                        "-p tcp -d {cidr} -j REDIRECT --to-ports {}",
                        config.outbound_port
                    ),
                ));
            }
        } else if include_cidrs.is_empty() {
            for port in &config.include_outbound_ports {
                commands.push(idempotent_append(
                    "nat",
                    "FERRUM_MESH_OUTBOUND",
                    &format!(
                        "-p tcp --dport {port} -j REDIRECT --to-ports {}",
                        config.outbound_port
                    ),
                ));
            }
        } else {
            for cidr in include_cidrs {
                for port in &config.include_outbound_ports {
                    commands.push(idempotent_append(
                        "nat",
                        "FERRUM_MESH_OUTBOUND",
                        &format!(
                            "-p tcp -d {cidr} --dport {port} -j REDIRECT --to-ports {}",
                            config.outbound_port
                        ),
                    ));
                }
            }
        }
        // Inbound port exclusions MUST be appended before the catch-all
        // REDIRECT below — once REDIRECT fires the chain returns, so any
        // RETURN rule placed after it would be silently bypassed.
        for port in &config.exclude_inbound_ports {
            commands.push(idempotent_append(
                "nat",
                "FERRUM_MESH_INBOUND",
                &format!("-p tcp --dport {port} -j RETURN"),
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
        vec![
            // Step 1: remove jump rules from built-in chains
            idempotent_delete("nat", "OUTPUT", "-p tcp -j FERRUM_MESH_OUTBOUND"),
            idempotent_delete("nat", "PREROUTING", "-p tcp -j FERRUM_MESH_INBOUND"),
            // Step 2: flush custom chains
            flush_chain("nat", "FERRUM_MESH_INBOUND"),
            flush_chain("nat", "FERRUM_MESH_OUTBOUND"),
            // Step 3: delete custom chains (must be empty first)
            delete_chain("nat", "FERRUM_MESH_INBOUND"),
            delete_chain("nat", "FERRUM_MESH_OUTBOUND"),
        ]
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

/// Returns true when `cidr` parses as a syntactically valid IPv4 CIDR. Used to
/// keep IPv6 CIDRs out of the iptables-IPv4 plan; admission validation has
/// already rejected malformed shapes, so a `false` here means a well-formed
/// IPv6 CIDR (or — defensively — anything else `validate_cidr_list` would have
/// accepted that is not IPv4). The IPv4 init container can only program IPv4
/// rules, so non-IPv4 CIDRs are skipped at plan-build time with a warning.
fn is_ipv4_cidr(cidr: &str) -> bool {
    cidr.split_once('/')
        .and_then(|(addr, _)| addr.parse::<IpAddr>().ok())
        .is_some_and(|ip| ip.is_ipv4())
}

fn idempotent_new_chain(table: &str, chain: &str) -> String {
    format!("iptables -t {table} -N {chain} 2>/dev/null || true")
}

fn idempotent_append(table: &str, chain: &str, rule: &str) -> String {
    format!(
        "iptables -t {table} -C {chain} {rule} 2>/dev/null || iptables -t {table} -A {chain} {rule}"
    )
}

fn idempotent_delete(table: &str, chain: &str, rule: &str) -> String {
    format!("iptables -t {table} -D {chain} {rule} 2>/dev/null || true")
}

fn flush_chain(table: &str, chain: &str) -> String {
    format!("iptables -t {table} -F {chain} 2>/dev/null || true")
}

fn delete_chain(table: &str, chain: &str) -> String {
    format!("iptables -t {table} -X {chain} 2>/dev/null || true")
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
    fn setup_then_cleanup_covers_all_chains() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.proxy_uid = Some(DEFAULT_PROXY_UID);

        let setup = IptablesPlan::for_config(&config);
        let cleanup = IptablesPlan::cleanup_commands();

        // Every custom chain created in setup must be deleted in cleanup
        let setup_chains: Vec<&str> = setup
            .commands
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
            .commands
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
                plan.commands
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
            .commands
            .iter()
            .position(|cmd| {
                cmd.contains("FERRUM_MESH_INBOUND")
                    && cmd.contains(&format!("REDIRECT --to-ports {}", config.inbound_port))
            })
            .expect("inbound REDIRECT command");
        for port in [15090, 22] {
            let return_pos = plan
                .commands
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
                .commands
                .iter()
                .any(|cmd| cmd.contains("FERRUM_MESH_INBOUND") && cmd.contains("-j RETURN")),
            "no inbound RETURN rules expected when exclude_inbound_ports is empty"
        );
    }

    #[test]
    fn iptables_plan_keeps_cidr_redirect_when_include_ports_empty() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["10.0.0.0/8".to_string()];

        let plan = IptablesPlan::for_config(&config);

        assert!(
            plan.commands
                .iter()
                .any(|cmd| cmd.contains("-p tcp -d 10.0.0.0/8 -j REDIRECT --to-ports 15001")),
            "CIDR-only include rule should remain when includeOutboundPorts is unset"
        );
    }

    #[test]
    fn iptables_plan_emits_per_port_redirects_when_include_ports_set() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_outbound_ports = vec![5432, 9092];

        let plan = IptablesPlan::for_config(&config);

        for port in [5432, 9092] {
            assert!(
                plan.commands.iter().any(|cmd| cmd.contains(&format!(
                    "-p tcp -d 0.0.0.0/0 --dport {port} -j REDIRECT --to-ports 15001"
                ))),
                "includeOutboundPorts REDIRECT missing for port {port}: {:?}",
                plan.commands
            );
        }
        assert!(
            !plan
                .commands
                .iter()
                .any(|cmd| cmd.contains("-p tcp -d 0.0.0.0/0 -j REDIRECT")),
            "port-scoped includes should replace the CIDR-only catch-all redirect"
        );
    }

    #[test]
    fn iptables_plan_combines_include_ports_with_include_cidrs() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["10.0.0.0/8".to_string()];
        config.include_outbound_ports = vec![5432];

        let plan = IptablesPlan::for_config(&config);

        assert!(
            plan.commands.iter().any(|cmd| cmd
                .contains("-p tcp -d 10.0.0.0/8 --dport 5432 -j REDIRECT --to-ports 15001")),
            "includeOutboundPorts should narrow the configured include CIDR: {:?}",
            plan.commands
        );
        assert!(
            !plan
                .commands
                .iter()
                .any(|cmd| cmd.contains("-p tcp -d 10.0.0.0/8 -j REDIRECT")),
            "CIDR-only redirect should not remain when ports narrow the include scope"
        );
    }

    #[test]
    fn iptables_plan_emits_any_ipv4_port_redirect_when_include_ports_and_only_ipv6_cidrs() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["fd00::/8".to_string()];
        config.include_outbound_ports = vec![5432];

        let plan = IptablesPlan::for_config(&config);

        assert!(
            plan.commands
                .iter()
                .any(|cmd| { cmd.contains("-p tcp --dport 5432 -j REDIRECT --to-ports 15001") }),
            "includeOutboundPorts should still emit a per-port redirect after IPv6 CIDRs are stripped: {:?}",
            plan.commands
        );
        assert!(
            !plan.commands.iter().any(|cmd| cmd.contains("fd00::/8")),
            "IPv6 include CIDR must not appear in the IPv4 iptables plan: {:?}",
            plan.commands
        );
    }

    #[test]
    fn iptables_plan_orders_exclude_port_before_overlapping_include_port() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.exclude_ports = vec![5432];
        config.include_outbound_ports = vec![5432];

        let plan = IptablesPlan::for_config(&config);
        let exclude_idx = plan
            .commands
            .iter()
            .position(|cmd| cmd.contains("-p tcp --dport 5432 -j RETURN"))
            .expect("exclude port RETURN rule should be emitted");
        let include_idx = plan
            .commands
            .iter()
            .position(|cmd| cmd.contains("--dport 5432 -j REDIRECT --to-ports 15001"))
            .expect("include port REDIRECT rule should be emitted");

        assert!(
            exclude_idx < include_idx,
            "excludeOutboundPorts must win over includeOutboundPorts by rule order: {:?}",
            plan.commands
        );
    }

    // The init container only invokes the IPv4 `iptables` binary. Passing an
    // IPv6 CIDR like `fd00::/8` as a raw `-d` argument makes the append fail
    // at runtime, which silently leaves the capture chain partially populated
    // (later rules in the same script never get applied if `set -e` is ever
    // added; today the operator only sees a stderr error and a half-built
    // chain). Drop non-IPv4 CIDRs from the plan and let the warn log surface
    // them — admission still accepts the annotation for forward compatibility
    // with the future ip6tables fan-out.
    #[test]
    fn iptables_plan_skips_ipv6_exclude_cidr() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.exclude_cidrs = vec!["10.0.0.0/8".to_string(), "fd00::/8".to_string()];

        let plan = IptablesPlan::for_config(&config);

        assert!(
            plan.commands
                .iter()
                .any(|cmd| cmd.contains("-d 10.0.0.0/8 -j RETURN")),
            "IPv4 exclude CIDR must still appear in the plan"
        );
        assert!(
            !plan.commands.iter().any(|cmd| cmd.contains("fd00::/8")),
            "IPv6 exclude CIDR must NOT appear in the plan (would fail at iptables -A): {:?}",
            plan.commands
        );
    }

    #[test]
    fn iptables_plan_skips_ipv6_include_cidr() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()];

        let plan = IptablesPlan::for_config(&config);

        assert!(
            plan.commands
                .iter()
                .any(|cmd| cmd.contains("-d 10.0.0.0/8 -j REDIRECT --to-ports 15001")),
            "IPv4 include CIDR must still appear in the plan"
        );
        assert!(
            !plan
                .commands
                .iter()
                .any(|cmd| cmd.contains("2001:db8::/32")),
            "IPv6 include CIDR must NOT appear in the plan (would fail at iptables -A): {:?}",
            plan.commands
        );
    }

    // Regression: an include list containing ONLY IPv6 CIDRs must not produce
    // any outbound REDIRECT rule. Earlier behavior would have emitted a single
    // broken `iptables -A ... -d {ipv6}/N -j REDIRECT` that left the OUTBOUND
    // chain redirect-less while the rest of the script (PREROUTING, INBOUND)
    // still applied — silently breaking outbound capture.
    #[test]
    fn iptables_plan_omits_outbound_redirect_when_only_ipv6_include() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["fd00::/8".to_string()];

        let plan = IptablesPlan::for_config(&config);

        assert!(
            !plan.commands.iter().any(|cmd| {
                cmd.contains("FERRUM_MESH_OUTBOUND") && cmd.contains("REDIRECT --to-ports 15001")
            }),
            "no outbound REDIRECT should be emitted when the only include CIDR is IPv6"
        );
    }

    #[test]
    fn is_ipv4_cidr_classifies_families() {
        assert!(is_ipv4_cidr("10.0.0.0/8"));
        assert!(is_ipv4_cidr("0.0.0.0/0"));
        assert!(is_ipv4_cidr("127.0.0.0/8"));
        assert!(!is_ipv4_cidr("fd00::/8"));
        assert!(!is_ipv4_cidr("2001:db8::/32"));
        assert!(!is_ipv4_cidr("::/0"));
        // Malformed shapes are not IPv4; admission validator catches these earlier.
        assert!(!is_ipv4_cidr("not-a-cidr"));
        assert!(!is_ipv4_cidr("10.0.0.0"));
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
}
