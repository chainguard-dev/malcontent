rule libc: harmless {
  strings:
    $signal      = "_signal" fullword
    $sigaction   = "sigaction" fullword
    $sigismember = "sigismember" fullword

  condition:
    any of them
}

