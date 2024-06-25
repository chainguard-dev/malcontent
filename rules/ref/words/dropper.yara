
rule decryptor : medium {
  meta:
    description = "References 'dropper'"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
  strings:
    $ref = "dropper" fullword
    $ref2 = "Dropper" fullword
  condition:
    any of them
}
