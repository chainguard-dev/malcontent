rule GOST89 {
  meta:
    description = "Uses the GOST89 block cipher"

  strings:
    $ref = "GOST89"

  condition:
    any of them
}
