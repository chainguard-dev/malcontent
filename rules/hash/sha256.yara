rule SHA256 {
  meta:
    description = "Uses the SHA256 signature format"

  strings:
    $ref = "SHA256_"

  condition:
    any of them
}
