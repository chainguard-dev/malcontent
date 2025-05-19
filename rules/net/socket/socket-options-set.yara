rule setsockopt: harmless {
  meta:
    description = "set socket options"
    syscall     = "setsockopt"

  strings:
    $setsockopt = "setsockopt" fullword
    $Setsockopt = "Setsockopt" fullword

  condition:
    any of them
}

rule go_setsockopt_int: medium {
  meta:
    description = "set socket options by integer"
    syscall     = "setsockopt"
    filetypes   = "elf,go,macho"

  strings:
    $setsockopt = "SetsockoptInt"

  condition:
    any of them
}
