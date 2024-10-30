rule setrlimit: harmless {
  meta:
    syscall     = "setrlimit"
    description = "set resource limits"
    pledge      = "id"

  strings:
    $ref = "setrlimit" fullword

  condition:
    any of them
}
