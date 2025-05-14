rule crypto_fnv {
  meta:
    description = "Uses FNV hash algorithm"

  strings:
    $ref = "hash/fnv"

  condition:
    any of them
}
