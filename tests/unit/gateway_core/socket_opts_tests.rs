//! Unit tests for platform-specific socket optimizations.

use ferrum_edge::socket_opts::*;

// Non-Linux no-ops
#[cfg(not(target_os = "linux"))]
#[test]
fn test_socket_opts_noop_on_non_linux() {
    assert!(set_ip_bind_address_no_port(0, true).is_ok());
    assert!(set_tcp_fastopen_server(0, 256).is_ok());
    assert!(set_tcp_fastopen_client(0).is_ok());
}
