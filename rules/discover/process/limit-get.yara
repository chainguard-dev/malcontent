rule getrlimit: harmless {
  meta:
    syscall     = "getrlimit"
    description = "retrieve resource limits"
    pledge      = "id"

  strings:
    $ref = "getrlimit" fullword
    $go  = "Getrlimit" fullword

  condition:
    any of them
}
