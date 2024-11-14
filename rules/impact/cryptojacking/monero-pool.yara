rule monero_pool: medium {
  meta:
    description              = "References Monero mining pools"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"

  strings:
    $ref  = "monero"
    $ref2 = "pool"

  condition:
    all of them
}
