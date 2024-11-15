rule hacktool_pspy: critical {
  meta:
    description = "tool to snoop on processes without root permissions"

  strings:
    $ref = "dominicbreuker/pspy"
    $f1  = "startFSW"
    $f2  = "startPSS"
    $f3  = "triggerEvery"

  condition:
    $ref or 2 of ($f*)
}
