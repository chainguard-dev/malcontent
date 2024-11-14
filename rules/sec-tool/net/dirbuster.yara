rule dirbuster: high {
  meta:
  strings:
    $ref = "dirbuster" fullword

  condition:
    $ref
}
