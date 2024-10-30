rule setpgid: harmless {
  meta:
    pledge  = "proc"
    syscall = "setpgid"

  strings:
    $setpgid = "setpgid" fullword
    $setpgrp = "setpgrp" fullword

  condition:
    any of them
}

