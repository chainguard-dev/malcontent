rule whirlpool: medium {
  meta:
    description = "hash function often used for cryptomining"
    ref         = "https://en.wikipedia.org/wiki/Whirlpool_(hash_function)"

  strings:
    $ref = "WHIRLPOOL" fullword

  condition:
    any of them
}
