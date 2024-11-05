rule libc: harmless {
  strings:
    $signal      = "_signal" fullword
    $sigaction   = "sigaction" fullword
    $sigismember = "sigismember" fullword

  condition:
    any of them
}

rule win_cntrl: low windows {
  meta:
    description = "Adds or removes handler function for the calling process"

  strings:
    $ref = "SetConsoleCtrlHandler"

  condition:
    any of them
}
