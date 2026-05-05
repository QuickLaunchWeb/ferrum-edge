use std::time::Duration;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::http3::config::{
    H3_RECEIVE_WINDOW_DEFAULT, H3_SEND_WINDOW_DEFAULT, H3_STREAM_RECEIVE_WINDOW_DEFAULT,
    Http3ServerConfig,
};

#[test]
fn test_http3_server_config_default_values() {
    let config = Http3ServerConfig::default();

    assert_eq!(config.max_concurrent_streams, 1000);
    assert_eq!(config.idle_timeout, Duration::from_secs(30));
    assert_eq!(
        config.stream_receive_window,
        H3_STREAM_RECEIVE_WINDOW_DEFAULT
    );
    assert_eq!(config.receive_window, H3_RECEIVE_WINDOW_DEFAULT);
    assert_eq!(config.send_window, H3_SEND_WINDOW_DEFAULT);
    assert_eq!(config.initial_mtu, 1500);
    // Default mirrors EnvConfig::default().frontend_tls_handshake_timeout_seconds (10s).
    assert_eq!(config.handshake_timeout, Duration::from_secs(10));
}

#[test]
fn test_http3_server_config_handshake_timeout_from_env_config() {
    // Non-zero value: forwarded as Duration::from_secs.
    let env = EnvConfig {
        frontend_tls_handshake_timeout_seconds: 7,
        ..Default::default()
    };
    let config = Http3ServerConfig::from_env_config(&env);
    assert_eq!(config.handshake_timeout, Duration::from_secs(7));
}

#[test]
fn test_http3_server_config_handshake_timeout_zero_disables() {
    // 0 disables — forwarded as Duration::ZERO so the listener can branch on
    // `.is_zero()` to skip the `tokio::time::timeout` wrapper. Mirrors the
    // TCP/TLS and DTLS frontend "0 disables" semantic.
    let env = EnvConfig {
        frontend_tls_handshake_timeout_seconds: 0,
        ..Default::default()
    };
    let config = Http3ServerConfig::from_env_config(&env);
    assert_eq!(config.handshake_timeout, Duration::ZERO);
    assert!(config.handshake_timeout.is_zero());
}

#[test]
fn test_http3_server_config_default_env_propagates_handshake_timeout() {
    // EnvConfig::default() default for frontend_tls_handshake_timeout_seconds
    // is 10 seconds and must round-trip through Http3ServerConfig.
    let env = EnvConfig::default();
    let config = Http3ServerConfig::from_env_config(&env);
    assert_eq!(
        config.handshake_timeout,
        Duration::from_secs(env.frontend_tls_handshake_timeout_seconds)
    );
    assert_eq!(config.handshake_timeout, Duration::from_secs(10));
}

#[test]
fn test_http3_server_config_initial_mtu_from_env() {
    let env = EnvConfig {
        http3_initial_mtu: 1350,
        ..Default::default()
    };

    let config = Http3ServerConfig::from_env_config(&env);
    assert_eq!(config.initial_mtu, 1350);
}

#[test]
fn test_http3_server_config_from_env_config_defaults() {
    // EnvConfig::default() should produce the same values as Http3ServerConfig::default()
    let env = EnvConfig::default();
    let config = Http3ServerConfig::from_env_config(&env);

    assert_eq!(config.max_concurrent_streams, 1000);
    assert_eq!(config.idle_timeout, Duration::from_secs(30));
    assert_eq!(
        config.stream_receive_window,
        H3_STREAM_RECEIVE_WINDOW_DEFAULT
    );
    assert_eq!(config.receive_window, H3_RECEIVE_WINDOW_DEFAULT);
    assert_eq!(config.send_window, H3_SEND_WINDOW_DEFAULT);
}

#[test]
fn test_http3_server_config_from_env_config_custom_values() {
    let env = EnvConfig {
        http3_max_streams: 500,
        http3_idle_timeout: 60,
        http3_stream_receive_window: 4_194_304, // 4 MiB
        http3_receive_window: 16_777_216,       // 16 MiB
        http3_send_window: 2_097_152,           // 2 MiB
        ..Default::default()
    };

    let config = Http3ServerConfig::from_env_config(&env);

    assert_eq!(config.max_concurrent_streams, 500);
    assert_eq!(config.idle_timeout, Duration::from_secs(60));
    assert_eq!(config.stream_receive_window, 4_194_304);
    assert_eq!(config.receive_window, 16_777_216);
    assert_eq!(config.send_window, 2_097_152);
}

#[test]
fn test_http3_server_config_from_env_config_zero_idle_timeout() {
    let env = EnvConfig {
        http3_idle_timeout: 0,
        ..Default::default()
    };

    let config = Http3ServerConfig::from_env_config(&env);

    assert_eq!(config.idle_timeout, Duration::from_secs(0));
}

#[test]
fn test_http3_server_config_from_env_config_large_windows() {
    let env = EnvConfig {
        http3_stream_receive_window: 128 * 1024 * 1024, // 128 MiB
        http3_receive_window: 512 * 1024 * 1024,        // 512 MiB
        http3_send_window: 64 * 1024 * 1024,            // 64 MiB
        ..Default::default()
    };

    let config = Http3ServerConfig::from_env_config(&env);

    assert_eq!(config.stream_receive_window, 128 * 1024 * 1024);
    assert_eq!(config.receive_window, 512 * 1024 * 1024);
    assert_eq!(config.send_window, 64 * 1024 * 1024);
}

#[test]
fn test_http3_server_config_from_env_config_min_streams() {
    let env = EnvConfig {
        http3_max_streams: 1,
        ..Default::default()
    };

    let config = Http3ServerConfig::from_env_config(&env);

    assert_eq!(config.max_concurrent_streams, 1);
}
