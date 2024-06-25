
rule hacktool_pspy : critical {
  meta:
    description = "tool to snoop on processes without root permissions"
    hash_2024_processmonitoring_pspy32 = "1e38ac09d7851b22e16980abc58f93cabdc4a02859c56a2810aa51930277d450"
    hash_2024_processmonitoring_pspy64 = "c93f29a5cc1347bdb90e14a12424e6469c8cfea9a20b800bc249755f0043a3bb"
  strings:
    $ref = "dominicbreuker/pspy"
    $f1 = "startFSW"
    $f2 = "startPSS"
    $f3 = "triggerEvery"
  condition:
    $ref or 2 of ($f*)
}
