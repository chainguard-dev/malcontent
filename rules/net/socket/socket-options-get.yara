rule getsockopt: harmless {
  meta:
    description = "get socket options"
    syscall     = "getsockopt"

  strings:
    $setsockopt = "getsockopt" fullword

  condition:
    any of them
}
