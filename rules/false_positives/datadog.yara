rule default_policy: override {
  meta:
    SIGNATURE_BASE_P0Wnedpotato = "harmless"
    multiple_pools              = "harmless"
    polkit_pkexec_exploit       = "harmless"

  strings:
    $datadog = "# IMPORTANT: Edits to this file will not be reflected in the Datadog App and will be overwritten with new policy file downloads. Please modify rules in the Datadog App for full functionality."
    $version = /version: \d+\.\d+\.\d+/
    $type    = "type: policy"

  condition:
    filesize < 256KB and all of them
}

rule datadog_agent_binary: override {
  meta:
    description               = "datadog-agent binary"
    binary_url_with_question  = "medium"
    iplookup_website          = "medium"
    etc_ld_preload_not_ld     = "medium"
    ipinfo_and_bash           = "medium"
    linux_network_filter_exec = "medium"
    go_memfd_create           = "medium"

  strings:
    $datadog_module = "github.com/DataDog/datadog-agent"
    $datadoghq      = "datadoghq.com"

  condition:
    filesize < 500MB and all of them
}
