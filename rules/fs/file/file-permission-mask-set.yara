rule umask: harmless {
  meta:
    description = "set file mode creation mask"

  strings:
    $ref = "umask" fullword

  condition:
    any of them
}
