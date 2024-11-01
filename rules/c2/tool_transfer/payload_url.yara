rule payload_url: high {
  meta:
    description              = "References a 'payload URL'"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"

  strings:
    $ref  = "payload_url" fullword
    $ref2 = "payload url" fullword
    $ref3 = "payload URL" fullword

  condition:
    any of them
}
