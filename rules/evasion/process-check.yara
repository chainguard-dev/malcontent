
rule activity_monitor_checker : suspicious {
  strings:
    $ps = "ps" fullword
    $pgrep = "pgrep" fullword
    $am = "Activity Monitor" fullword
  condition:
    $am and any of ($p*)
}
