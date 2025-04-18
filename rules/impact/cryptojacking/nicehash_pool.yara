rule nicehash_pool: high {
  meta:
    description = "References Nicehash and mining pools"

  strings:
    $ref            = "nicehash" fullword
    $ref2           = "pool"
    $not_pypi_index = "testpack-id-lb001"

  condition:
    all of ($ref*) and none of ($not*)
}
