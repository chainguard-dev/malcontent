rule vhangup {
  meta:
    syscall     = "vhangup"
    capability  = "CAP_SYS_TTY_CONFIG"
    description = "virtually hangup the current terminal"

  strings:
    $ref = "vhangup" fullword

  condition:
    any of them
}
