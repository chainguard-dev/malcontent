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

rule wazuh_agentd: override {
  meta:
    description             = "/var/ossec/bin/wazuh-agentd — Wazuh HIDS agent daemon"
    rootkit                 = "medium"
    rootkit_high            = "medium"
    curl_easy_exfil         = "low"
    load_agent_with_payload = "low"

  strings:
    $wazuh_agentd = "wazuh-agentd" fullword
    $libwazuhext  = "libwazuhext.so"
    $ossec_conf   = "etc/ossec.conf"
    $wazuh_home   = "Wazuh home directory: %s"
    $reload_agent = "reloadAgent" fullword

  condition:
    filesize < 2MB and all of them
}

rule wazuh_syscheckd: override {
  meta:
    description         = "/var/ossec/bin/wazuh-syscheckd — Wazuh file integrity monitoring / rootcheck daemon"
    rootkit             = "medium"
    rootkit_high        = "medium"
    cmd_dev_null_quoted = "medium"
    proc_s_exe          = "medium"

  strings:
    $libwazuhext   = "libwazuhext.so"
    $wazuh_db_lost = "Connection with wazuh-db lost. Reconnecting."
    $docker_mod    = "wazuh-modulesd:docker-listener"
    $cti_api       = "https://cti.wazuh.com/api/v1/catalog/"
    $audit_rules   = "/etc/audit/rules.d/audit_rules_wazuh.rules"

  condition:
    filesize < 2MB and all of them
}
