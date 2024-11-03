rule blockchain: medium override {
  meta:
    description = "Uses a blockchain"

  strings:
    $ref = "blockchain"

  condition:
    any of them
}
