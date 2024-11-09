rule nodejs_buffer_from: medium {
  meta:
    description = "loads arbitrary bytes from a buffer"

  strings:
    $ref = /Buffer\.from\(\[[\d,]{8,63}\)/

  condition:
    any of them
}

rule nodejs_buffer_from_many: high {
  meta:
    description             = "loads many arbitrary bytes from a buffer"
    hash_2017_package_post  = "7664e04586d294092c86b7203f0651d071a993c5d62875988c2c5474e554c0e8"
    hash_2017_package_post  = "451ee8116592bf6148e25b0a65a12813639a663b1292b925fa95ed64d4185d0c"
    hash_1985_package_index = "451ee8116592bf6148e25b0a65a12813639a663b1292b925fa95ed64d4185d0c"

  strings:
    $ref = /Buffer\.from\(\[[\d,]{63,2048}/

  condition:
    any of them
}

