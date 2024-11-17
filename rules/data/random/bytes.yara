rule generate_rand {
  meta:
    description = "generates random bytes"

  strings:
    $ref = ".randomBytes(" fullword

  condition:
    any of them
}
