rule fcntl: harmless {
  meta:
    pledge      = "wpath"
    description = "manipulate file descriptor with fcntl"
  // sometimes CAP_LEASE

  strings:
    $ref = "fcntl" fullword

  condition:
    any of them
}
