rule wazuh_policy_monitoring: override {
  meta:
    description              = "wazuh-dashboard policy-monitoring.js sample data"
    hidden_short_path_system = "low"
    hidden_short_path_temp   = "low"
    rootkit                  = "low"

  strings:
    $wazuh_dashboard   = "wazuh-dashboard"
    $policy_monitoring = "policy-monitoring"

  condition:
    filesize < 5MB and all of them
}
