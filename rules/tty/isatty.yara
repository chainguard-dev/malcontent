rule isatty: harmless {
  meta:
    description = "checks if file handle refers to a terminal"

  strings:
    $ref = "isatty" fullword

  condition:
    any of them
}
