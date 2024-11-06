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
    description         = "securitySolution.chunk.9.js"

  strings:
    $license           = "Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V."
    $license2          = "Licensed under the Elastic License 2.0"
    $security_solution = "securitySolution"
    $xpac              = "xpac"

  condition:
    filesize < 5MB and all of them
}
