rule crypto_fernet: medium {
  meta:
    description = "Supports Fernet (symmetric encryption)"

  strings:
    $ref  = "fernet" fullword
    $ref2 = "Fernet" fullword

  condition:
    any of them
}
