rule whirlpool: medium {
  meta:
    description              = "hash function often used for cryptomining"
    ref                      = "https://en.wikipedia.org/wiki/Whirlpool_(hash_function)"
    hash_2023_Downloads_06ab = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"

  strings:
    $ref = "WHIRLPOOL" fullword

  condition:
    any of them
}
