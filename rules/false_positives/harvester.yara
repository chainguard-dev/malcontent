rule harvester_ui_plugin: override {
  meta:
    description                  = "harvester-v1.8.0.umd.min.js - Harvester UI plugin (Rancher HCI platform)"
    unsigned_bitwise_math_excess = "low"
    unsigned_bitwise_math        = "low"
    static_charcode_math         = "low"
    hardcoded_host_port_over_10k = "low"
    hardcoded_host_port          = "low"
    charAtBitwise                = "low"

  strings:
    $harvester_cluster = "harvester-common/getHarvesterClusterUrl"
    $cattle_monitoring = "cattle-monitoring-system"

  condition:
    filesize < 4MB and all of them
}
