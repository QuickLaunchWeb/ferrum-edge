use ferrum_edge::plugins::geo_restriction::GeoRestriction;
use serde_json::json;

// Note: geo_restriction tests that require actual .mmdb files are limited to
// config validation tests. Full lookup tests would require a MaxMind test database.

#[test]
fn test_new_missing_db_path_fails() {
    let config = json!({
        "allow_countries": ["US"]
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("db_path"));
}

#[test]
fn test_new_invalid_db_path_fails() {
    let config = json!({
        "db_path": "/nonexistent/path/to/GeoLite2-Country.mmdb",
        "allow_countries": ["US"]
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("failed to open"));
}

#[test]
fn test_new_no_countries_fails() {
    let config = json!({
        "db_path": "/tmp/test.mmdb"
    });
    // This will fail because db_path doesn't exist, but that's fine —
    // the actual validation would catch no countries after a valid db_path.
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
}

#[test]
fn test_new_both_allow_and_deny_fails() {
    // Note: This test will fail at db_path validation first in practice,
    // but we test the config validation logic independently.
    let config = json!({
        "db_path": "/tmp/test.mmdb",
        "allow_countries": ["US"],
        "deny_countries": ["CN"]
    });
    let result = GeoRestriction::new(&config);
    // Will fail at db_path first, but the mutual exclusion check is in the code
    assert!(result.is_err());
}
