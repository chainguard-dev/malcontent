rule blockchain: medium {
  meta:
    description = "Uses a blockchain"

  strings:
    $ref = "blockchain"

  condition:
    any of them
}
