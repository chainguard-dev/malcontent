rule systemsetup_no_sleep: medium {
  meta:
    description = "disables sleep mode"

  strings:
    $no_sleep = "systemsetup -setcomputersleep Never"

  condition:
    filesize < 10485760 and any of them
}
