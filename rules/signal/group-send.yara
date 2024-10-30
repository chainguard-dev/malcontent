rule killpg: harmless {
  meta:
    syscall = "kill"
    pledge  = "proc"

  strings:
    $kill = "_killpg" fullword

  condition:
    any of them
}
