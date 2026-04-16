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

rule wazuh_mitre_db: override {
  meta:
    description                                            = "MITRE ATT&CK database shipped with Wazuh Manager"
    SIGNATURE_BASE_Hacktool_Strings_P0Wnedshell            = "harmless"
    SIGNATURE_BASE_Mimikatz_Memory_Rule_1                  = "harmless"
    SIGNATURE_BASE_APT_UA_Hermetic_Wiper_Artefacts_Feb22_1 = "harmless"
    KPortScan                                              = "harmless"
    RDPWrap                                                = "harmless"
    security_dump_keychain                                 = "low"
    fake_kworker                                           = "low"
    hacktool_mimikatz                                      = "low"

  strings:
    $mitre_attack_pattern = "attack-pattern--"
    $mitre_detection      = "mitre_detection"
    $create_technique     = "CREATE TABLE technique"

  condition:
    filesize > 10MB and filesize < 20MB and all of them
}
