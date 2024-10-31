rule SHA512: harmless {
  meta:
    description = "Uses the SHA512 signature format"

  strings:
    $ref = "SHA512"

  condition:
    any of them
}
