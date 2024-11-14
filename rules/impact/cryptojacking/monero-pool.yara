rule monero_pool: medium {
  meta:
    description = "References Monero mining pools"

  strings:
    $ref  = "monero"
    $ref2 = "pool"

  condition:
    all of them
}
