rule kibana_powershell_evasion_rule: override {
  meta:
    description            = "defense_evasion_defender_exclusion_via_powershell.json"
    win_defender_exclusion = "low"

  strings:
    $elastic = "Elastic"
    $eql     = "\"language\": \"eql\""
    $name    = "Windows Defender Exclusions Added via PowerShell"

  condition:
    filesize < 8KB and all of them
}

rule security_solution_plugin: override {
  meta:
    linux_rootkit_terms = "low"
    masscan             = "low"
    reverse_shell       = "low"
    grayware_sites      = "low"
    http_url_with_exe   = "Low"
    exotic_tld          = "low"
    download_sites      = "low"
    description         = "securitySolution.chunk.9.js, securitySolution.chunk.22.js"

  strings:
    $license           = "Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V."
    $license2          = "Licensed under the Elastic License 2.0"
    $jsonp             = "window.securitySolution_bundle_jsonpfunction"
    $security_solution = "securitySolution"
    $xpac              = "xpac"

  condition:
    filesize < 5MB and all of ($license*) and $security_solution and ($jsonp or $xpac)
}

rule security_detection_engine: override {
  meta:
    casing_obfuscation                          = "low"
    dev_shm_hidden                              = "low"
    hacktool_mimikatz                           = "low"
    linux_rootkit_terms                         = "low"
    polkit_pkexec_exploit                       = "low"
    SIGNATURE_BASE_Hacktool_Strings_P0Wnedshell = "low"
    SIGNATURE_BASE_HKTL_Domainpasswordspray     = "low"
    SIGNATURE_BASE_P0Wnedpotato                 = "low"
    SIGNATURE_BASE_Wmimplant                    = "low"
    win_defender_exclusion                      = "low"
    hidden_short_path_system                    = "low"

  strings:
    $attr1   = "rule_id"
    $attr2   = "query"
    $attr3   = "required_fields"
    $attr4   = "risk_score"
    $attr5   = "severity"
    $attr6   = "type"
    $elastic = "Elastic"
    $rule    = "security-rule"

  condition:
    filesize < 32KB and 68 % of ($attr*) and $elastic and $rule
}
