rule clickhouse_binary : override {
  meta:
    malware_PlugX_config = "high"
    description = "clickhouse"
    original_severity = "critical"
  strings:
    $clickhouse_binary = "/usr/bin/clickhouse"
    $clickhouse_client = "clickhouse-client"
    $clickhouse_service = /clickhouse-\w{0,32}/ fullword
    $clickhouse_server = "clickhouse-server"
    $clickhouse_site = "https://clickhouse.com"
    $usage = "Usage: ./clickhouse"
  condition:
    all of them
}
