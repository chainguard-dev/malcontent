
rule systemsetup_no_sleep : notable {
  strings:
    $no_sleep = "systemsetup -setcomputersleep Never"
  condition:
    filesize < 10485760 and any of them
}
