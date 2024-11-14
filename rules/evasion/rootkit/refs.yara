rule rootkit_l33t: high {
  meta:
    description = "references a 'rootkit'"

    hash_2024_D3m0n1z3dShell_demonizedshell = "d7c34b9d711260c1cd001ca761f5df37cbe40b492f198b228916b6647b660119"
    hash_2024_scripts_implant_rootkit       = "c7ffb802c0e2813e2b0edba2efe8fa660740806b902cd1f1aea01c998812206d"

  strings:
    $s_r00tkit = "r00tkit"
    $s_r00tk1t = "r00tk1t"

  condition:
    any of them
}

rule rootkit: medium {
  meta:
    description = "references a 'rootkit'"

    hash_2022_LQvKibDTq4_diamorphine = "aec68cfa75b582616c8fbce22eecf463ddb0c09b692a1b82a8de23fb0203fede"
    hash_2023_LQvKibDTq4_diamorphine = "e93e524797907d57cb37effc8ebe14e6968f6bca899600561971e39dfd49831d"

  strings:
    $s_rootkit = "rootkit" fullword
    $s_Rootkit = "Rootkit" fullword

  condition:
    any of them
}

rule rootkit_high: high {
  meta:
    description = "references a 'rootkit'"

    hash_2022_LQvKibDTq4_diamorphine = "aec68cfa75b582616c8fbce22eecf463ddb0c09b692a1b82a8de23fb0203fede"
    hash_2023_LQvKibDTq4_diamorphine = "e93e524797907d57cb37effc8ebe14e6968f6bca899600561971e39dfd49831d"

  strings:
    $s_rootkit     = "rootkit" fullword
    $s_Rootkit     = "Rootkit" fullword
    $not_phishing  = "phishing" fullword
    $not_keylogger = "keylogger" fullword

  condition:
    filesize < 10MB and any of ($s*) and none of ($not*)
}
