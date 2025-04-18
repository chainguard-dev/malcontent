rule cryptonight: high {
  meta:
    description = "References CryptoNight, a proof-of-work algorithm"

  strings:
    $ref            = "cryptonight"
    $ref2           = "Cryptonight"
    $not_pypi_index = "testpack-id-lb001"

  condition:
    any of ($ref*) and none of ($not*)
}
