rule freeport: medium {
  meta:
    description = "find open TCP port to listen at"

  strings:
    $ref = "phayes/freeport"

  condition:
    any of them
}
