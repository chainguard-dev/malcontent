
rule pipe_to_bg : medium {
  meta:
    description = "pipes to backgrounded shell"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"
  strings:
    $ref = "| sh &"
  condition:
    $ref
}
