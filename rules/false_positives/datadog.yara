rule default_policy: override {
  meta:
    SIGNATURE_BASE_P0Wnedpotato = "harmless"
    multiple_pools              = "harmless"
    polkit_pkexec_exploit       = "harmless"

  strings:
    $datadog = "# IMPORTANT: Edits to this file will not be reflected in the Datadog App and will be overwritten with new policy file downloads. Please modify rules in the Datadog App for full functionality."
    $version = /version: [0-9]\.[0-9]{1,3}\.[0-9]{1,3}/
    $type    = "type: policy"

  condition:
    filesize < 256KB and all of them
}
