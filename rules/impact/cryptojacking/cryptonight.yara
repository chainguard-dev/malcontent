rule cryptonight: high {
  meta:
    description = "References CryptoNight, a proof-of-work algorithm"

  strings:
    $ref  = "cryptonight"
    $ref2 = "Cryptonight"

  condition:
    any of them
}
