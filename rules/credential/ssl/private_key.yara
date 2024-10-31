rule private_key_val {
  meta:
    description = "References private keys"

  strings:
    $ref  = "private_key"
    $ref2 = "PRIVATE_KEY"
    $ref3 = "privateKey"
    $ref4 = "privatekey"

  condition:
    any of them
}
