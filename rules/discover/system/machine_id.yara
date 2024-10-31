rule machineid {
  meta:
    description = "Gets a unique machineid for the host"

  strings:
    $ref = "machineid"

  condition:
    any of them
}
