rule SHA1 {
  meta:
    description = "Uses the SHA1 signature format"

  strings:
    $ref = "SHA1_"

  condition:
    any of them
}
