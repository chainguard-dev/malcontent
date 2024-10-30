rule terminfo: harmless {
  meta:
    description = "uses the terminfo capability database"

  strings:
    $ref = "terminfo" fullword

  condition:
    any of them
}
