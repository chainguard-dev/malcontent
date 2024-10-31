rule os_log: harmless {
  meta:
    description = "Use the macOS system log service"

  strings:
    $ref = "os_log" fullword

  condition:
    all of them
}
