
rule killed_all : medium {
  meta:
    description = "References 'killed all'"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"
  strings:
    $ref = /killed all[\w ]+/
  condition:
    any of them
}

rule killed_format : medium {
  meta:
    description = "References 'killed %d'"
  strings:
    $ref = /[Kk]illed %d/
  condition:
    any of them
}
