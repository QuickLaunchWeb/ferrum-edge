use ferrum_edge::plugins::Plugin;
use ferrum_edge::plugins::workload_metrics::WorkloadMetrics;
use serde_json::json;

use super::plugin_utils::create_test_transaction_summary;

#[tokio::test]
async fn workload_metrics_counts_http_transactions() {
    let plugin = WorkloadMetrics::new(&json!({})).unwrap();
    let mut summary = create_test_transaction_summary();
    summary.metadata.insert(
        "source_principal".to_string(),
        "spiffe://cluster.local/ns/default/sa/client".to_string(),
    );

    plugin.log(&summary).await;

    assert_eq!(plugin.http_transactions(), 1);
}
