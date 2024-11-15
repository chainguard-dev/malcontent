rule dirbuster: high {
  meta:
    description = "brute-force tool for guessing website directories"

  strings:
    $ref = "dirbuster" fullword

  condition:
    $ref
}
