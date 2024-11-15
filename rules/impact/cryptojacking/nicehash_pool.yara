rule nicehash_pool: high {
  meta:
    description = "References Nicehash and mining pools"

  strings:
    $ref  = "nicehash"
    $ref2 = "pool"

  condition:
    all of them
}
